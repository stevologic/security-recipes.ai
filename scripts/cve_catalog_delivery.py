#!/usr/bin/env python3
"""Retry-safe decisions for CVE catalog PR delivery.

Data-only catalog PRs skip karen-qa and the GitHub App check. If branch
protection still blocks the merge, the sync leaves the PR open and retries
on the next run instead of failing. Non-data-only diffs fail closed.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.cve_catalog_data_paths import catalog_revision_content_matches
except (ImportError, ModuleNotFoundError):  # Direct ``python scripts/...`` execution.
    from cve_catalog_data_paths import catalog_revision_content_matches  # type: ignore[no-redef]

ALERT_ACTIONS = frozenset(
    {
        "fail_closed_not_data_only",
        "fail_closed_sha_mismatch",
        "fail_closed_real_checks",
        "fail_closed_missing_in_run_validation",
        "fail_closed_head_mismatch",
        "fail_unexpected",
        "identity_changed",
        "merged_wrong_sha",
        "fail_fallback_escalated",
        "fail_generated_output_review",
    }
)
SYNC_BRANCH = "automation/cve-catalog-sync"
GENERATED_OUTPUT_BRANCH = "automation/cve-generated-outputs"
WRONG_SHA_CHECKPOINTS = (
    "before_validation",
    "after_validation",
    "after_merge_attempt",
)
FALLBACK_LABEL = "automation:protection-fallback"
KAREN_QA_REVIEW_LABEL = "needs karen-qa"
FALLBACK_CONSECUTIVE_RUNS = 2
FALLBACK_MAX_AGE = timedelta(hours=24)
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


def merged_sha_matches(*, head_sha: str, merge_commit_sha: str, expected_sha: str) -> bool:
    """True when a merged PR's head or merge SHA is the exact expected revision."""

    expected = (expected_sha or "").strip()
    if not expected:
        return False
    return expected in {(head_sha or "").strip(), (merge_commit_sha or "").strip()}


def merged_revision_matches(
    *,
    head_sha: str,
    merge_commit_sha: str,
    expected_sha: str,
    content_matches: bool | None = None,
    repo: Path | None = None,
    fetch: bool = False,
) -> bool:
    """Accept a merged PR when its SHA or merge-commit catalog content matches.

    Squash and merge commits mint a new SHA. Those are idempotent when the
    merge commit's allowlisted catalog-data-path blobs match the expected
    revision and the full expected...merge diff is data-only. The PR head is
    not a content candidate. ``content_matches=True`` is not a success path.
    Unknown or mismatched catalog content fails closed.
    """

    if merged_sha_matches(
        head_sha=head_sha,
        merge_commit_sha=merge_commit_sha,
        expected_sha=expected_sha,
    ):
        return True
    if content_matches is False:
        return False
    del content_matches  # True is not a success path; always verify the merge commit.
    return catalog_revision_content_matches(
        expected_sha=expected_sha,
        candidate_shas=(merge_commit_sha,),
        repo=repo,
        fetch=fetch,
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
    merge_commit_sha: str = "",
    content_matches: bool | None = None,
    repo: Path | None = None,
    fetch: bool = False,
) -> str:
    if merged:
        if merged_revision_matches(
            head_sha=head_sha,
            merge_commit_sha=merge_commit_sha,
            expected_sha=expected_sha,
            content_matches=content_matches,
            repo=repo,
            fetch=fetch,
        ):
            return "already_merged"
        return "merged_wrong_sha"
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


def parse_github_datetime(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class FallbackDecision:
    escalate: bool
    action: str
    message: str
    consecutive_runs: int
    age_hours: float

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def _app_unconfigured_note(app_configured: bool) -> str:
    if app_configured:
        return ""
    return (
        " GitHub App is not configured; set CVE_SYNC_APP_ID and "
        "CVE_SYNC_APP_KEY on the cve-sync environment."
    )


def classify_protection_fallback(
    *,
    already_labeled: bool,
    labeled_at: str = "",
    now: datetime | None = None,
    app_configured: bool = False,
) -> FallbackDecision:
    """Escalate when the App is missing, after 2 fallback runs, or after 24h.

    Age is measured from the fallback label, never from the PR's created_at.
    A first fallback on a long-lived catalog PR is not an alert when the
    GitHub App is configured. A missing App fails closed on the first run.
    """

    clock = now or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)
    else:
        clock = clock.astimezone(timezone.utc)
    if not app_configured:
        labeled = parse_github_datetime(labeled_at)
        age = (clock - labeled) if labeled is not None else timedelta(0)
        return FallbackDecision(
            escalate=True,
            action="fail_fallback_escalated",
            message=(
                "GitHub App is not configured; set CVE_SYNC_APP_ID and "
                "CVE_SYNC_APP_KEY on the cve-sync environment. Catalog merge "
                "cannot bypass ruleset 18147261 without the App. Failing "
                "closed on the first run."
            ),
            consecutive_runs=FALLBACK_CONSECUTIVE_RUNS if already_labeled else 1,
            age_hours=max(0.0, age.total_seconds() / 3600),
        )
    consecutive = FALLBACK_CONSECUTIVE_RUNS if already_labeled else 1
    labeled = parse_github_datetime(labeled_at)
    if already_labeled and labeled is None:
        return FallbackDecision(
            escalate=True,
            action="fail_fallback_escalated",
            message=(
                "Catalog protection-fallback label is present but has an invalid "
                "labeled_at timestamp; failing closed as a real alert."
                + _app_unconfigured_note(app_configured)
            ),
            consecutive_runs=consecutive,
            age_hours=0.0,
        )
    age = (clock - labeled) if labeled is not None else timedelta(0)
    age_hours = max(0.0, age.total_seconds() / 3600)
    if consecutive >= FALLBACK_CONSECUTIVE_RUNS:
        return FallbackDecision(
            escalate=True,
            action="fail_fallback_escalated",
            message=(
                "Catalog PR has been in protection-fallback on 2 consecutive "
                "sync runs; escalating to a real alert."
                + _app_unconfigured_note(app_configured)
            ),
            consecutive_runs=consecutive,
            age_hours=age_hours,
        )
    if labeled is not None and age >= FALLBACK_MAX_AGE:
        return FallbackDecision(
            escalate=True,
            action="fail_fallback_escalated",
            message=(
                "Catalog protection-fallback label is older than 24h; "
                "escalating to a real alert."
                + _app_unconfigured_note(app_configured)
            ),
            consecutive_runs=consecutive,
            age_hours=age_hours,
        )
    return FallbackDecision(
        escalate=False,
        action="protection_fallback",
        message=(
            "Data-only catalog merge is blocked by branch protection; "
            "leaving the PR open for the next sync retry."
            + _app_unconfigured_note(app_configured)
        ),
        consecutive_runs=consecutive,
        age_hours=age_hours,
    )


def fail_closed_merged_wrong_sha(*, checkpoint: str, pr_state: str) -> int:
    """Fail closed at each delivery-loop wrong-SHA checkpoint.

    The workflow invokes this at every named checkpoint. Removing any one
    checkpoint, or treating ``merged_wrong_sha`` as success there, is a
    real alert failure.
    """

    if checkpoint not in WRONG_SHA_CHECKPOINTS:
        print(
            f"::error::unknown merged-wrong-SHA checkpoint: {checkpoint}",
            file=sys.stderr,
        )
        return 1
    if pr_state != "merged_wrong_sha":
        return 0
    print(
        "::error::Catalog PR already merged, but its head/merge SHA is not "
        f"the expected SHA; failing closed at {checkpoint}.",
        file=sys.stderr,
    )
    return 1


@dataclass(frozen=True)
class GeneratedOutputReviewDecision:
    failed: bool
    escalate: bool
    action: str
    message: str

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    def exit_code(self) -> int:
        return 1 if self.failed else 0


def classify_generated_output_review(*, step_failed: bool) -> GeneratedOutputReviewDecision:
    """A review PR that fails to open is a real alert, not a warning."""

    if not step_failed:
        return GeneratedOutputReviewDecision(
            failed=False,
            escalate=False,
            action="generated_output_ok",
            message=(
                "Generated-output review PR opened or had no behaviour-changing "
                "changes."
            ),
        )
    return GeneratedOutputReviewDecision(
        failed=True,
        escalate=True,
        action="fail_generated_output_review",
        message=(
            "Generated-output review PR failed to open; escalating as a real "
            "alert. The CVE catalog PR is unaffected and already continued."
        ),
    )


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

    fallback = sub.add_parser("fallback-escalation")
    fallback.add_argument("--already-labeled", required=True, choices=("true", "false"))
    fallback.add_argument("--labeled-at", default="")
    fallback.add_argument("--now", default="")
    fallback.add_argument("--app-configured", default="false", choices=("true", "false"))

    wrong_sha = sub.add_parser("fail-closed-wrong-sha")
    wrong_sha.add_argument("--checkpoint", required=True)
    wrong_sha.add_argument("--pr-state", required=True)

    review = sub.add_parser("generated-output-review")
    review.add_argument("--step-failed", required=True, choices=("true", "false"))

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
            merge_commit_sha=str(payload.get("merge_commit_sha") or ""),
            repo=Path.cwd(),
            fetch=True,
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
    if args.command == "fallback-escalation":
        clock = parse_github_datetime(args.now) if args.now else None
        decision = classify_protection_fallback(
            already_labeled=_flag(args.already_labeled),
            labeled_at=args.labeled_at,
            now=clock,
            app_configured=_flag(args.app_configured),
        )
        print(json.dumps(decision.to_json(), indent=2, sort_keys=True))
        return 0
    if args.command == "fail-closed-wrong-sha":
        return fail_closed_merged_wrong_sha(
            checkpoint=args.checkpoint,
            pr_state=args.pr_state,
        )
    if args.command == "generated-output-review":
        decision = classify_generated_output_review(step_failed=_flag(args.step_failed))
        print(json.dumps(decision.to_json(), indent=2, sort_keys=True))
        return decision.exit_code()
    raise SystemExit(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
