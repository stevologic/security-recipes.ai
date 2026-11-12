# Karen QA #483 r2 mutants at d085ddbc: (id, file, old, new). Each old must occur exactly once.
SH = ".github/workflows/automation-shepherd.yml"
VA = ".github/workflows/cve-catalog-validate.yml"
CHK = 'if [ "$CHECK_RUNS" -gt 0 ] || [ "$STATUSES" -gt 0 ]; then'
CASE_FAIL = '            failure|cancelled|skipped)\n              STATE=failure'
LIVE = '''          if [ "$PR_STATE" != "open" ] ||
             [ "$HEAD_REPOSITORY" != "$GITHUB_REPOSITORY" ] ||
             [ "$HEAD_BRANCH" != "$EXPECTED_BRANCH" ] ||
             [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ] ||
             [ "$HEAD_SHA" != "$EXPECTED_SHA" ] ||
             [ "$BASE_BRANCH" != "$DEFAULT_BRANCH" ]; then'''
def drop(line):  # remove one conjunct line from LIVE
    return LIVE.replace(line, "", 1)
MUTANTS = [
 # ---- B1: YAML env wiring ----
 ("B1-K12-validate-result-hardcoded", VA, "VALIDATE_RESULT: ${{ needs.validate.result }}", "VALIDATE_RESULT: success"),
 ("B1-K13-expected-sha-github-sha", VA, "          EXPECTED_SHA: ${{ inputs.expected_sha }}\n          EXPECTED_BRANCH:", "          EXPECTED_SHA: ${{ github.sha }}\n          EXPECTED_BRANCH:"),
 ("B1-a-reject-step-sha-github-sha", VA, "      - name: Reject a missing or invalid exact SHA\n        shell: bash\n        env:\n          EXPECTED_SHA: ${{ inputs.expected_sha }}", "      - name: Reject a missing or invalid exact SHA\n        shell: bash\n        env:\n          EXPECTED_SHA: ${{ github.sha }}"),
 ("B1-b-shepherd-default-branch-ref-name", SH, "          GITHUB_DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}\n        run: |\n          # Guarded updates", "          GITHUB_DEFAULT_BRANCH: ${{ github.ref_name }}\n        run: |\n          # Guarded updates"),
 ("B1-c-pr-number-from-run-id", VA, "PR_NUMBER: ${{ inputs.pr_number }}", "PR_NUMBER: ${{ github.run_id }}"),
 ("B1-d-expected-branch-hardcoded", VA, "EXPECTED_BRANCH: ${{ inputs.expected_branch }}", "EXPECTED_BRANCH: automation/cve-catalog-sync"),
 ("B1-e-pulls-path-wrong-pr", VA, '"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}"', '"repos/${GITHUB_REPOSITORY}/pulls/1"'),
 # ---- B2: shepherd skip paths ----
 ("B2-K6-drop-statuses-or", SH, CHK, 'if [ "$CHECK_RUNS" -gt 0 ]; then'),
 ("B2-K6b-drop-checkruns-or", SH, CHK, 'if [ "$STATUSES" -gt 0 ]; then'),
 ("B2-K6c-status-any-context", SH, "--jq '[.statuses[] | select(.context == \"build\")] | length'", "--jq '[.statuses[]] | length'"),
 ("B2-K6d-checkrun-any-name", SH, "--jq '[.check_runs[] | select(.name == \"build\")] | length'", "--jq '[.check_runs[]] | length'"),
 ("B2-K4a-drop-queued", SH, "for RUN_STATUS in queued in_progress pending waiting requested; do", "for RUN_STATUS in in_progress pending waiting requested; do"),
 ("B2-K4b-drop-in_progress", SH, "for RUN_STATUS in queued in_progress pending waiting requested; do", "for RUN_STATUS in queued pending waiting requested; do"),
 ("B2-K4c-drop-pending", SH, "for RUN_STATUS in queued in_progress pending waiting requested; do", "for RUN_STATUS in queued in_progress waiting requested; do"),
 ("B2-K4d-drop-waiting", SH, "for RUN_STATUS in queued in_progress pending waiting requested; do", "for RUN_STATUS in queued in_progress pending requested; do"),
 ("B2-K4e-drop-requested", SH, "for RUN_STATUS in queued in_progress pending waiting requested; do", "for RUN_STATUS in queued in_progress pending waiting; do"),
 ("B2-K3-dedupe-key-drops-sha", SH, 'select(.displayTitle | endswith(\\"@ ${HEAD_SHA}\\"))', 'select(.displayTitle | startswith(\\"CVE catalog validation\\"))'),
 ("B2-K5-no-accumulate", SH, "PENDING_VALIDATIONS=$((PENDING_VALIDATIONS + STATUS_COUNT))", "PENDING_VALIDATIONS=$((STATUS_COUNT))"),
 ("B2-K7-pending-gt-1", SH, 'if [ "$PENDING_VALIDATIONS" -gt 0 ]; then', 'if [ "$PENDING_VALIDATIONS" -gt 1 ]; then'),
 ("B2-M3-dedupe-if-false", SH, 'if [ "$PENDING_VALIDATIONS" -gt 0 ]; then', 'if false; then'),
 ("B2-K1-z-guard", SH, '            if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then', '            if [ -z "$HEAD_SHA" ]; then'),
 ("B2-K2-unanchored", SH, '            if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then', '            if [[ ! "$HEAD_SHA" =~ [0-9a-f]{40} ]]; then'),
 ("B2-K2b-no-end-anchor", SH, '            if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then', '            if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40} ]]; then'),
 ("B2-K2c-any-length-hex", SH, '            if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then', '            if [[ ! "$HEAD_SHA" =~ ^[0-9a-f]+$ ]]; then'),
 ("B2-M6-guard-continue-true", SH, '              echo "::error::#${PR_NUMBER}: missing or invalid head SHA; refusing to dispatch validation."\n              continue', '              echo "::error::#${PR_NUMBER}: missing or invalid head SHA; refusing to dispatch validation."\n              true'),
 # ---- B3: result mapping ----
 ("B3-K8-failure-posts-success", VA, CASE_FAIL, '            failure|cancelled|skipped)\n              STATE=success'),
 ("B3-K9-failure-only", VA, '            failure|cancelled|skipped)', '            failure)'),
 ("B3-K9a-drop-cancelled", VA, '            failure|cancelled|skipped)', '            failure|skipped)'),
 ("B3-K9b-drop-skipped", VA, '            failure|cancelled|skipped)', '            failure|cancelled)'),
 ("B3-K10-unknown-posts-success", VA, '              echo "::error::Unknown validate result ${VALIDATE_RESULT}; refusing to publish a build status."\n              exit 1', '              STATE=success\n              DESCRIPTION=unknown'),
 ("B3-K10b-empty-joins-success", VA, '            success)\n              STATE=success', '            success|"")\n              STATE=success'),
 ("B3-K10c-success-posts-failure", VA, '            success)\n              STATE=success', '            success)\n              STATE=failure'),
 ("B3-K10d-unknown-posts-failure", VA, '              echo "::error::Unknown validate result ${VALIDATE_RESULT}; refusing to publish a build status."\n              exit 1', '              STATE=failure\n              DESCRIPTION=unknown'),
 # ---- Scope (Kenny): shepherd ----
 ("S-K17-drop-shepherd-filter", SH, '            if [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not', '            if false; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not'),
 ("S-K18-prefix-filter", SH, '            if [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not', '            if [[ "$HEAD_BRANCH" != automation/* ]]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not'),
 ("S-K19-substring-filter", SH, '            if [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not', '            if [[ "$HEAD_BRANCH" != *cve-catalog-sync* ]]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not'),
 ("S-a-suffix-filter", SH, '            if [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not', '            if [[ "$HEAD_BRANCH" != *automation/cve-catalog-sync ]]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not'),
 ("S-b-prefix-of-sync", SH, '            if [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not', '            if [[ "$HEAD_BRANCH" != automation/cve-catalog-sync* ]]; then\n              echo "#${PR_NUMBER}: ${HEAD_BRANCH} is not'),
 ("S-c-filter-after-dispatch-field-head", SH, '--field "expected_branch=${SYNC_BRANCH}"', '--field "expected_branch=${HEAD_BRANCH}"'),
 ("S-d-drop-crossrepo-select", SH, "            | select(.isCrossRepository == false)\n", ""),
 # ---- Scope: publish gate ----
 ("P-a-drop-expected-branch-sync-check", VA, '          if [ "$EXPECTED_BRANCH" != "$SYNC_BRANCH" ]; then', '          if false; then'),
 ("P-b-drop-live-branch-sync", VA, LIVE, drop('             [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ] ||\n')),
 ("P-ab-drop-both-sync-checks", VA, '          if [ "$EXPECTED_BRANCH" != "$SYNC_BRANCH" ]; then', '          if false; then'),  # + second edit below
 ("P-c-drop-head-repo-check", VA, LIVE, drop('             [ "$HEAD_REPOSITORY" != "$GITHUB_REPOSITORY" ] ||\n')),
 ("P-d-drop-state-open", VA, LIVE, LIVE.replace('          if [ "$PR_STATE" != "open" ] ||\n             [ "$HEAD_REPOSITORY"', '          if [ "$HEAD_REPOSITORY"', 1)),
 ("P-e-drop-base-check", VA, LIVE, LIVE.replace(' ||\n             [ "$BASE_BRANCH" != "$DEFAULT_BRANCH" ]; then', '; then', 1)),
 ("P-f-drop-head-eq-expected-branch", VA, LIVE, drop('             [ "$HEAD_BRANCH" != "$EXPECTED_BRANCH" ] ||\n')),
 ("P-K20-drop-head-sha-check", VA, LIVE, drop('             [ "$HEAD_SHA" != "$EXPECTED_SHA" ] ||\n')),
 ("P-g-head-repo-default-self", VA, """HEAD_REPOSITORY="$(jq -r '.head.repo.full_name // ""' <<<"$PR_JSON")\"""", """HEAD_REPOSITORY="$(jq -r --arg r "$GITHUB_REPOSITORY" '.head.repo.full_name // $r' <<<"$PR_JSON")\""""),
 ("P-h-publish-prefix-both", VA, '          if [ "$EXPECTED_BRANCH" != "$SYNC_BRANCH" ]; then', '          if [[ "$EXPECTED_BRANCH" != automation/* ]]; then'),  # + second edit below
 # ---- Retry cap (N=4 attempts) ----
 ("R-a-max-1", VA, "local max_attempts=4", "local max_attempts=1"),
 ("R-b-max-2", VA, "local max_attempts=4", "local max_attempts=2"),
 ("R-c-max-3", VA, "local max_attempts=4", "local max_attempts=3"),
 ("R-d-max-5", VA, "local max_attempts=4", "local max_attempts=5"),
 ("R-e-ge-to-gt", VA, 'if [ "$attempt" -ge "$max_attempts" ]; then', 'if [ "$attempt" -gt "$max_attempts" ]; then'),
 ("R-f-post-without-retry", VA, "          gh_api_with_retry --method POST \\", "          gh api --method POST \\"),
]
# second edits for compound mutants: id -> (file, old, new)
EXTRA = {
 "P-ab-drop-both-sync-checks": (VA, '             [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ] ||\n', ''),
 "P-h-publish-prefix-both": (VA, '             [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ] ||\n', '             [[ "$HEAD_BRANCH" != automation/* ]] ||\n'),
}
MUTANTS.append(("P-i-publish-prefix-of-sync-both", VA, '          if [ "$EXPECTED_BRANCH" != "$SYNC_BRANCH" ]; then', '          if [[ "$EXPECTED_BRANCH" != automation/cve-catalog-sync* ]]; then'))
EXTRA["P-i-publish-prefix-of-sync-both"] = (VA, '             [ "$HEAD_BRANCH" != "$SYNC_BRANCH" ] ||\n', '             [[ "$HEAD_BRANCH" != automation/cve-catalog-sync* ]] ||\n')

# Kenny dispatch-origin guard (added after the production guard landed)
MUTANTS += [
 ("D1-drop-ref-check", VA,
  """          if [ "$DISPATCH_REF" != "$TRUSTED_REF" ] ||
             [ "$DISPATCH_ACTOR" != "$TRUSTED_ACTOR" ]; then""",
  '          if [ "$DISPATCH_ACTOR" != "$TRUSTED_ACTOR" ]; then'),
 ("D2-ref-prefix", VA,
  '          if [ "$DISPATCH_REF" != "$TRUSTED_REF" ] ||',
  '          if [[ "$DISPATCH_REF" != refs/heads/main* ]] ||'),
 ("D3-drop-actor-check", VA,
  """          if [ "$DISPATCH_REF" != "$TRUSTED_REF" ] ||
             [ "$DISPATCH_ACTOR" != "$TRUSTED_ACTOR" ]; then""",
  '          if [ "$DISPATCH_REF" != "$TRUSTED_REF" ]; then'),
 ("D4-actor-substring", VA,
  '             [ "$DISPATCH_ACTOR" != "$TRUSTED_ACTOR" ]; then',
  '             [[ "$DISPATCH_ACTOR" != *github-actions* ]]; then'),
 ("D5-guard-exit-0", VA,
  """            echo "::error::Refusing to publish a self-posted build; dispatch was not from ${TRUSTED_REF} by ${TRUSTED_ACTOR}."
            exit 1""",
  """            echo "::error::Refusing to publish a self-posted build; dispatch was not from ${TRUSTED_REF} by ${TRUSTED_ACTOR}."
            exit 0"""),
]
