"""On-disk mutant specs applied to live workflow files at test time."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SH = ".github/workflows/automation-shepherd.yml"
VA = ".github/workflows/cve-catalog-validate.yml"
CHK = 'if [ "$CHECK_RUNS" -gt 0 ] || [ "$STATUSES" -gt 0 ]; then'
LIVE = """          if [ "$PR_STATE" != "open" ] ||
             [ "$HEAD_REPOSITORY" != "$GITHUB_REPOSITORY" ] ||
             [ "$HEAD_BRANCH" != "$EXPECTED_BRANCH" ] ||
             [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ] ||
             [ "$HEAD_SHA" != "$EXPECTED_SHA" ] ||
             [ "$BASE_BRANCH" != "$DEFAULT_BRANCH" ]; then"""
ACTOR_ELIF = (
    '          elif [ -n "$APP_SLUG" ] && [ "$DISPATCH_ACTOR" = "$TRUSTED_APP_ACTOR" ]; then'
)
REF_OR_ACTOR = """          if [ "$DISPATCH_REF" != "$TRUSTED_REF" ] ||
             [ "$actor_ok" -ne 1 ]; then"""
REFUSE_EXIT = """            echo "::error::Refusing to publish a self-posted build; dispatch was not from ${TRUSTED_REF} by a trusted actor."
            exit 1"""
PUBLISH_IF = """    if: always() && github.event_name == 'workflow_dispatch'
    needs:
      - validate
    permissions:
      contents: read
      pull-requests: read
      statuses: write"""
KICK_NEEDS = """    needs:
      - validate
      - publish-build-status"""
SHEPHERD_FILTER = """            if [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ]; then
              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not ${SYNC_BRANCH}; leaving required build to build.yml."
              continue
            fi"""
DEDUPE_BLOCK = """            # Query in-flight statuses directly so a pile of completed
            # validation runs cannot hide a queued/in-progress one.
            PENDING_VALIDATIONS=0
            for RUN_STATUS in queued in_progress pending waiting requested; do
              STATUS_COUNT="$(gh run list \\
                --workflow cve-catalog-validate.yml \\
                --status "$RUN_STATUS" \\
                --limit 50 \\
                --json displayTitle \\
                --jq "[.[] | select(.displayTitle | endswith(\\"@ ${HEAD_SHA}\\"))] | length")"
              PENDING_VALIDATIONS=$((PENDING_VALIDATIONS + STATUS_COUNT))
            done
            if [ "$PENDING_VALIDATIONS" -gt 0 ]; then
              echo "#${PR_NUMBER}: an exact-SHA validation is already running for ${HEAD_SHA}."
              continue
            fi

"""
HEAD_SHA_GUARD = """            if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then
              echo "::error::#${PR_NUMBER}: missing or invalid head SHA; refusing to dispatch validation."
              continue
            fi

"""
IDENTITY_GUARD = """          if [[ ! "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]] ||
             [[ ! "$PR_NUMBER" =~ ^[0-9]+$ ]] ||
             [ -z "$EXPECTED_BRANCH" ]; then
            echo "::error::Missing or invalid exact-SHA publish identity; refusing to publish a build status."
            exit 1
          fi
"""


def drop_live(line: str) -> str:
    return LIVE.replace(line, "", 1)


# (id, relative workflow path, old, new). Each old must occur exactly once.
MUTANTS: list[tuple[str, str, str, str]] = [
    ("B1-K12-validate-result-hardcoded", VA, "VALIDATE_RESULT: ${{ needs.validate.result }}", "VALIDATE_RESULT: success"),
    (
        "B1-K13-expected-sha-github-sha",
        VA,
        "          EXPECTED_SHA: ${{ inputs.expected_sha }}\n          EXPECTED_BRANCH:",
        "          EXPECTED_SHA: ${{ github.sha }}\n          EXPECTED_BRANCH:",
    ),
    (
        "B1-a-reject-step-sha-github-sha",
        VA,
        "      - name: Reject a missing or invalid exact SHA\n        shell: bash\n        env:\n          EXPECTED_SHA: ${{ inputs.expected_sha }}",
        "      - name: Reject a missing or invalid exact SHA\n        shell: bash\n        env:\n          EXPECTED_SHA: ${{ github.sha }}",
    ),
    (
        "B1-b-shepherd-default-branch-ref-name",
        SH,
        "          GITHUB_DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}\n        run: |\n          # Guarded updates",
        "          GITHUB_DEFAULT_BRANCH: ${{ github.ref_name }}\n        run: |\n          # Guarded updates",
    ),
    ("B1-c-pr-number-from-run-id", VA, "PR_NUMBER: ${{ inputs.pr_number }}", "PR_NUMBER: ${{ github.run_id }}"),
    ("B1-d-expected-branch-hardcoded", VA, "EXPECTED_BRANCH: ${{ inputs.expected_branch }}", "EXPECTED_BRANCH: automation/cve-catalog-sync"),
    ("B1-e-pulls-path-wrong-pr", VA, '"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}"', '"repos/${GITHUB_REPOSITORY}/pulls/1"'),
    ("B2-K6-drop-statuses-or", SH, CHK, 'if [ "$CHECK_RUNS" -gt 0 ]; then'),
    ("B2-K6b-drop-checkruns-or", SH, CHK, 'if [ "$STATUSES" -gt 0 ]; then'),
    (
        "B2-K6c-status-any-context",
        SH,
        '--jq \'[.statuses[] | select(.context == "build")] | length\'',
        "--jq '[.statuses[]] | length'",
    ),
    (
        "B2-K6d-checkrun-any-name",
        SH,
        '--jq \'[.check_runs[] | select(.name == "build")] | length\'',
        "--jq '[.check_runs[]] | length'",
    ),
    (
        "B2-K4a-drop-queued",
        SH,
        "for RUN_STATUS in queued in_progress pending waiting requested; do",
        "for RUN_STATUS in in_progress pending waiting requested; do",
    ),
    (
        "B2-K4b-drop-in_progress",
        SH,
        "for RUN_STATUS in queued in_progress pending waiting requested; do",
        "for RUN_STATUS in queued pending waiting requested; do",
    ),
    (
        "B2-K4c-drop-pending",
        SH,
        "for RUN_STATUS in queued in_progress pending waiting requested; do",
        "for RUN_STATUS in queued in_progress waiting requested; do",
    ),
    (
        "B2-K4d-drop-waiting",
        SH,
        "for RUN_STATUS in queued in_progress pending waiting requested; do",
        "for RUN_STATUS in queued in_progress pending requested; do",
    ),
    (
        "B2-K4e-drop-requested",
        SH,
        "for RUN_STATUS in queued in_progress pending waiting requested; do",
        "for RUN_STATUS in queued in_progress pending waiting; do",
    ),
    (
        "B2-K3-dedupe-key-drops-sha",
        SH,
        'select(.displayTitle | endswith(\\"@ ${HEAD_SHA}\\"))',
        'select(.displayTitle | startswith(\\"CVE catalog validation\\"))',
    ),
    (
        "B2-K5-no-accumulate",
        SH,
        "PENDING_VALIDATIONS=$((PENDING_VALIDATIONS + STATUS_COUNT))",
        "PENDING_VALIDATIONS=$((STATUS_COUNT))",
    ),
    ("B2-K7-pending-gt-1", SH, 'if [ "$PENDING_VALIDATIONS" -gt 0 ]; then', 'if [ "$PENDING_VALIDATIONS" -gt 1 ]; then'),
    ("B2-M3-dedupe-if-false", SH, 'if [ "$PENDING_VALIDATIONS" -gt 0 ]; then', "if false; then"),
    (
        "B2-K1-z-guard",
        SH,
        '            if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then',
        '            if [ -z "$HEAD_SHA" ]; then',
    ),
    (
        "B2-K2-unanchored",
        SH,
        '            if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then',
        '            if [[ ! "$HEAD_SHA" =~ [0-9a-f]{40} ]]; then',
    ),
    (
        "B2-K2b-no-end-anchor",
        SH,
        '            if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then',
        '            if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40} ]]; then',
    ),
    (
        "B2-K2c-any-length-hex",
        SH,
        '            if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then',
        '            if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]+$ ]]; then',
    ),
    (
        "B2-M6-guard-continue-true",
        SH,
        '              echo "::error::#${PR_NUMBER}: missing or invalid head SHA; refusing to dispatch validation."\n              continue',
        '              echo "::error::#${PR_NUMBER}: missing or invalid head SHA; refusing to dispatch validation."\n              true',
    ),
    (
        "B3-K8-failure-posts-success",
        VA,
        "            failure|cancelled|skipped)\n              STATE=failure",
        "            failure|cancelled|skipped)\n              STATE=success",
    ),
    ("B3-K9-failure-only", VA, "            failure|cancelled|skipped)", "            failure)"),
    ("B3-K9a-drop-cancelled", VA, "            failure|cancelled|skipped)", "            failure|skipped)"),
    ("B3-K9b-drop-skipped", VA, "            failure|cancelled|skipped)", "            failure|cancelled)"),
    (
        "B3-K10-unknown-posts-success",
        VA,
        '              echo "::error::Unknown validate result ${VALIDATE_RESULT}; refusing to publish a build status."\n              exit 1',
        "              STATE=success\n              DESCRIPTION=unknown",
    ),
    ("B3-K10b-empty-joins-success", VA, "            success)\n              STATE=success", '            success|"")\n              STATE=success'),
    ("B3-K10c-success-posts-failure", VA, "            success)\n              STATE=success", "            success)\n              STATE=failure"),
    (
        "B3-K10d-unknown-posts-failure",
        VA,
        '              echo "::error::Unknown validate result ${VALIDATE_RESULT}; refusing to publish a build status."\n              exit 1',
        "              STATE=failure\n              DESCRIPTION=unknown",
    ),
    (
        "S-K17-drop-shepherd-filter",
        SH,
        '            if [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not',
        '            if false; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not',
    ),
    (
        "S-K18-prefix-filter",
        SH,
        '            if [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not',
        '            if [[ "$HEAD_BRANCH" != automation/* ]]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not',
    ),
    (
        "S-K19-substring-filter",
        SH,
        '            if [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not',
        '            if [[ "$HEAD_BRANCH" != *cve-catalog-sync* ]]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not',
    ),
    (
        "S-a-suffix-filter",
        SH,
        '            if [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not',
        '            if [[ "$HEAD_BRANCH" != *automation/cve-catalog-sync ]]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not',
    ),
    (
        "S-b-prefix-of-sync",
        SH,
        '            if [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not',
        '            if [[ "$HEAD_BRANCH" != automation/cve-catalog-sync* ]]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not',
    ),
    ("S-c-filter-after-dispatch-field-head", SH, '--field "expected_branch=${SYNC_BRANCH}"', '--field "expected_branch=${HEAD_BRANCH}"'),
    ("S-d-drop-crossrepo-select", SH, "            | select(.isCrossRepository == false)\n", ""),
    ("P-a-drop-expected-branch-sync-check", VA, '          if [ "$EXPECTED_BRANCH" != "$SYNC_BRANCH" ]; then', "          if false; then"),
    ("P-b-drop-live-branch-sync", VA, LIVE, drop_live('             [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ] ||\n')),
    ("P-ab-drop-both-sync-checks", VA, '          if [ "$EXPECTED_BRANCH" != "$SYNC_BRANCH" ]; then', "          if false; then"),
    ("P-c-drop-head-repo-check", VA, LIVE, drop_live('             [ "$HEAD_REPOSITORY" != "$GITHUB_REPOSITORY" ] ||\n')),
    (
        "P-d-drop-state-open",
        VA,
        LIVE,
        LIVE.replace(
            '          if [ "$PR_STATE" != "open" ] ||\n             [ "$HEAD_REPOSITORY"',
            '          if [ "$HEAD_REPOSITORY"',
            1,
        ),
    ),
    (
        "P-e-drop-base-check",
        VA,
        LIVE,
        LIVE.replace(' ||\n             [ "$BASE_BRANCH" != "$DEFAULT_BRANCH" ]; then', "; then", 1),
    ),
    ("P-f-drop-head-eq-expected-branch", VA, LIVE, drop_live('             [ "$HEAD_BRANCH" != "$EXPECTED_BRANCH" ] ||\n')),
    ("P-K20-drop-head-sha-check", VA, LIVE, drop_live('             [ "$HEAD_SHA" != "$EXPECTED_SHA" ] ||\n')),
    (
        "P-g-head-repo-default-self",
        VA,
        """HEAD_REPOSITORY="$(jq -r '.head.repo.full_name // ""' <<<"$PR_JSON")\"""",
        """HEAD_REPOSITORY="$(jq -r --arg r "$GITHUB_REPOSITORY" '.head.repo.full_name // $r' <<<"$PR_JSON")\"""",
    ),
    ("P-h-publish-prefix-both", VA, '          if [ "$EXPECTED_BRANCH" != "$SYNC_BRANCH" ]; then', '          if [[ "$EXPECTED_BRANCH" != automation/* ]]; then'),
    (
        "P-i-publish-prefix-of-sync-both",
        VA,
        '          if [ "$EXPECTED_BRANCH" != "$SYNC_BRANCH" ]; then',
        '          if [[ "$EXPECTED_BRANCH" != automation/cve-catalog-sync* ]]; then',
    ),
    ("R-a-max-1", VA, "local max_attempts=4", "local max_attempts=1"),
    ("R-b-max-2", VA, "local max_attempts=4", "local max_attempts=2"),
    ("R-c-max-3", VA, "local max_attempts=4", "local max_attempts=3"),
    ("R-d-max-5", VA, "local max_attempts=4", "local max_attempts=5"),
    ("R-e-ge-to-gt", VA, 'if [ "$attempt" -ge "$max_attempts" ]; then', 'if [ "$attempt" -gt "$max_attempts" ]; then'),
    ("R-f-post-without-retry", VA, "          gh_api_with_retry --method POST \\", "          gh api --method POST \\"),
    ("M1-post-on-main", VA, '"repos/${GITHUB_REPOSITORY}/statuses/${EXPECTED_SHA}"', '"repos/${GITHUB_REPOSITORY}/statuses/${GITHUB_SHA}"'),
    ("M2-drop-sha-input", SH, '              --field "expected_sha=${HEAD_SHA}" \\\n', ""),
    ("M3-drop-dedupe", SH, DEDUPE_BLOCK, ""),
    ("M4-fail-open-missing-sha", VA, IDENTITY_GUARD, ""),
    ("M5-wrong-context-name", VA, '--raw-field "context=build"', '--raw-field "context=validation"'),
    ("M6-shepherd-fail-open-missing-sha", SH, HEAD_SHA_GUARD, ""),
    (
        "K11-drop-target-url",
        VA,
        '            --raw-field "description=${DESCRIPTION}" \\\n            --raw-field "target_url=${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"',
        '            --raw-field "description=${DESCRIPTION}"',
    ),
    (
        "K14-drop-always",
        VA,
        PUBLISH_IF,
        """    if: github.event_name == 'workflow_dispatch'
    needs:
      - validate
    permissions:
      contents: read
      pull-requests: read
      statuses: write""",
    ),
    (
        "K15-statuses-not-write",
        VA,
        "      contents: read\n      pull-requests: read\n      statuses: write",
        "      contents: read\n      pull-requests: read",
    ),
    ("K16-kick-without-publish", VA, KICK_NEEDS, "    needs:\n      - validate"),
    ("K17-drop-catalog-sync-filter", SH, SHEPHERD_FILTER, ""),
    ("D1-drop-ref-check", VA, REF_OR_ACTOR, '          if [ "$actor_ok" -ne 1 ]; then'),
    ("D2-ref-prefix", VA, '          if [ "$DISPATCH_REF" != "$TRUSTED_REF" ] ||', '          if [[ "$DISPATCH_REF" != refs/heads/main* ]] ||'),
    ("D2c-ref-suffix-main", VA, '          if [ "$DISPATCH_REF" != "$TRUSTED_REF" ] ||', '          if [[ "$DISPATCH_REF" != *main ]] ||'),
    ("D3-drop-actor-check", VA, REF_OR_ACTOR, '          if [ "$DISPATCH_REF" != "$TRUSTED_REF" ]; then'),
    (
        "D4-actor-substring",
        VA,
        '          if [ "$DISPATCH_ACTOR" = "$TRUSTED_ACTOR" ]; then',
        '          if [[ "$DISPATCH_ACTOR" == *github-actions* ]]; then',
    ),
    ("D5-guard-exit-0", VA, REFUSE_EXIT, REFUSE_EXIT.replace("exit 1", "exit 0")),
    (
        "F-lookalike-bot",
        VA,
        ACTOR_ELIF,
        '          elif [ -n "$APP_SLUG" ] && [[ "$DISPATCH_ACTOR" == "${APP_SLUG}"* ]]; then',
    ),
    ("F-any-bot", VA, ACTOR_ELIF, '          elif [[ "$DISPATCH_ACTOR" == *"[bot]" ]]; then'),
    (
        "F-unset-accepts-app",
        VA,
        ACTOR_ELIF,
        '          elif [ -z "$APP_SLUG" ] || [ "$DISPATCH_ACTOR" = "$TRUSTED_APP_ACTOR" ]; then',
    ),
    (
        "F-app-on-non-main",
        VA,
        REF_OR_ACTOR,
        """          if { [ "$DISPATCH_REF" != "$TRUSTED_REF" ] && [ "$DISPATCH_ACTOR" != "$TRUSTED_APP_ACTOR" ]; } ||
             [ "$actor_ok" -ne 1 ]; then""",
    ),
    (
        "F-loosened-slug",
        VA,
        ACTOR_ELIF,
        '          elif [ -n "$APP_SLUG" ] && [[ "$DISPATCH_ACTOR" == *"${APP_SLUG}"* ]]; then',
    ),
]

EXTRA: dict[str, tuple[str, str, str]] = {
    "P-ab-drop-both-sync-checks": (VA, '             [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ] ||\n', ""),
    "P-h-publish-prefix-both": (
        VA,
        '             [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ] ||\n',
        '             [[ "$HEAD_BRANCH" != automation/* ]] ||\n',
    ),
    "P-i-publish-prefix-of-sync-both": (
        VA,
        '             [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ] ||\n',
        '             [[ "$HEAD_BRANCH" != automation/cve-catalog-sync* ]] ||\n',
    ),
}

ALIASES = {
    "K1-null-head-z-guard": "B2-K1-z-guard",
    "K2-unanchored-sha-regex": "B2-K2-unanchored",
    "K3-dedupe-without-sha": "B2-K3-dedupe-key-drops-sha",
    "K4-drop-queued": "B2-K4a-drop-queued",
    "K5-assign-not-accumulate": "B2-K5-no-accumulate",
    "K6-drop-statuses-or": "B2-K6-drop-statuses-or",
    "K7-pending-gt-one": "B2-K7-pending-gt-1",
    "K8-failure-posts-success": "B3-K8-failure-posts-success",
    "K9-cancelled-skipped-unmapped": "B3-K9-failure-only",
    "K10-unknown-posts-success": "B3-K10-unknown-posts-success",
    "K12-hardcoded-validate-result": "B1-K12-validate-result-hardcoded",
    "K13-expected-sha-github-sha": "B1-K13-expected-sha-github-sha",
    "K18-prefix-catalog-filter": "S-K18-prefix-filter",
    "K19-substring-catalog-filter": "S-K19-substring-filter",
    "K20-drop-live-head-check": "P-K20-drop-head-sha-check",
}

EQUIVALENT_MUTANTS = frozenset(
    {
        "S-c-filter-after-dispatch-field-head",
        "P-a-drop-expected-branch-sync-check",
        "P-b-drop-live-branch-sync",
        "P-f-drop-head-eq-expected-branch",
    }
)


def _index() -> dict[str, tuple[str, str, str]]:
    return {item[0]: item[1:] for item in MUTANTS}


def edits_for(mutant_id: str) -> list[tuple[str, str, str]]:
    catalog = _index()
    source_id = ALIASES.get(mutant_id, mutant_id)
    if source_id not in catalog:
        raise KeyError(f"unknown mutant {mutant_id}")
    rel, old, new = catalog[source_id]
    edits = [(rel, old, new)]
    extra = EXTRA.get(source_id)
    if extra is not None:
        edits.append(extra)
    return edits


def known_mutant_ids() -> tuple[str, ...]:
    return tuple(item[0] for item in MUTANTS) + tuple(ALIASES)


def apply_edits(dest_root: Path, mutant_id: str) -> None:
    mapping = {
        SH: dest_root / "automation-shepherd.yml",
        VA: dest_root / "cve-catalog-validate.yml",
    }
    for rel, old, new in edits_for(mutant_id):
        path = mapping[rel]
        text = path.read_text(encoding="utf-8")
        count = text.count(old)
        if count != 1:
            raise AssertionError(f"{mutant_id}: {rel} old string occurs {count} times")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
