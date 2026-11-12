"""Disk mutants for the CVE catalog missing-App fallback. Named before running."""

from __future__ import annotations

WORKFLOW = ".github/workflows/cve-catalog-sync.yml"

# Each tuple is (id, relative path, exact old text, replacement).
MUTANTS: list[tuple[str, str, str, str]] = [
    (
        "M1_restore_early_exit",
        WORKFLOW,
        '        run: |\n          if [ "$CREDENTIAL_STATUS" = "incomplete" ]; then',
        '        run: |\n          echo "::error::GitHub App is not configured"\n          exit 1\n          if [ "$CREDENTIAL_STATUS" = "incomplete" ]; then',
    ),
    (
        "M2_drop_dispatch",
        WORKFLOW,
        '            gh workflow run cve-catalog-validate.yml \\\n              --ref "$VALIDATION_REF" \\\n              --field "expected_sha=$EXPECTED_SHA" \\\n              --field "request_id=$request_id" \\\n              --field "pr_number=$PR_NUMBER" \\\n              --field "expected_branch=$BRANCH"\n',
        "            echo skipped-validate-dispatch\n",
    ),
    (
        "M3_drop_exact_sha_input",
        WORKFLOW,
        '              --ref "$VALIDATION_REF" \\\n              --field "expected_sha=$EXPECTED_SHA" \\\n',
        '              --ref "$VALIDATION_REF" \\\n',
    ),
    (
        "M4_incomplete_pass",
        WORKFLOW,
        'if [ "$CREDENTIAL_STATUS" = "incomplete" ]; then',
        'if [ "$CREDENTIAL_STATUS" = "never-incomplete" ]; then',
    ),
    (
        "M5_key_only_as_missing",
        WORKFLOW,
        'if [ -n "$APP_ID" ] || [ -n "$APP_PRIVATE_KEY" ]; then',
        'if [ -n "$APP_ID" ]; then',
    ),
    (
        "M6_id_only_as_missing",
        WORKFLOW,
        'if [ -n "$APP_ID" ] || [ -n "$APP_PRIVATE_KEY" ]; then',
        'if [ -n "$APP_PRIVATE_KEY" ]; then',
    ),
    (
        "M7_skip_merge_inverted",
        WORKFLOW,
        '            if [ "$APP_CONFIGURED" != "true" ]; then\n              if ! report_protection_fallback',
        '            if [ "$APP_CONFIGURED" = "true" ]; then\n              if ! report_protection_fallback',
    ),
    (
        "M8_app_token_switch_inverted",
        WORKFLOW,
        '          if [ "$APP_CONFIGURED" = "true" ]; then\n            if [ -z "$APP_TOKEN" ]; then',
        '          if [ "$APP_CONFIGURED" != "true" ]; then\n            if [ -z "$APP_TOKEN" ]; then',
    ),
    (
        "M9_fallback_branch_dropped",
        WORKFLOW,
        '            if [ "$APP_CONFIGURED" != "true" ]; then\n              echo "::notice::GitHub App is not configured;',
        '            if false; then\n              echo "::notice::GitHub App is not configured;',
    ),
    (
        "M10_dispatch_ref_main",
        WORKFLOW,
        '            gh workflow run cve-catalog-validate.yml \\\n              --ref "$VALIDATION_REF" \\',
        '            gh workflow run cve-catalog-validate.yml \\\n              --ref "$GITHUB_DEFAULT_BRANCH" \\',
    ),
    (
        "M11_expected_sha_fallback_dropped",
        WORKFLOW,
        "EXPECTED_SHA: ${{ steps.app-commit.outputs.head_sha || needs.sync.outputs.head_sha }}",
        "EXPECTED_SHA: ${{ steps.app-commit.outputs.head_sha }}",
    ),
    (
        "M12_mint_if_dropped",
        WORKFLOW,
        "        id: app-token\n        if: steps.automation-auth.outputs.app_configured == 'true'\n",
        "        id: app-token\n",
    ),
    (
        "M13_empty_app_token_guard_dropped",
        WORKFLOW,
        '            if [ -z "$APP_TOKEN" ]; then\n              echo "::error::GitHub App is configured but no App token was minted; failing closed."\n              exit 1\n            fi\n',
        "",
    ),
    (
        "M14_actions_permission_read",
        WORKFLOW,
        "    timeout-minutes: 60\n    permissions:\n      actions: write\n",
        "    timeout-minutes: 60\n    permissions:\n      actions: read\n",
    ),
    (
        "M15_fallback_label_dropped",
        WORKFLOW,
        '            gh pr edit "$PR_NUMBER" --add-label "automation:protection-fallback"\n            echo "head_sha=${expected_sha}" >> "$GITHUB_OUTPUT"\n',
        '            echo "head_sha=${expected_sha}" >> "$GITHUB_OUTPUT"\n',
    ),
    (
        "M16_fallback_output_dropped",
        WORKFLOW,
        '              echo "protection_fallback=true" >> "$GITHUB_OUTPUT"\n              if [ "$escalate" = "true" ]; then\n                echo "::error::$message"\n                echo "::error::Catalog protection-fallback escalated after 2 consecutive runs or 24h; this is a real alert."\n                return 1\n              fi\n              return 0\n',
        '              if [ "$escalate" = "true" ]; then\n                echo "::error::$message"\n                echo "::error::Catalog protection-fallback escalated after 2 consecutive runs or 24h; this is a real alert."\n                return 1\n              fi\n              return 0\n',
    ),
]

KILLERS: dict[str, str] = {
    "M1_restore_early_exit": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_missing_app_run1_dispatches_validate_skips_merge_and_labels",
    "M2_drop_dispatch": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_missing_app_run1_dispatches_validate_skips_merge_and_labels",
    "M3_drop_exact_sha_input": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_missing_app_validate_dispatch_pins_exact_sha_on_pr_branch",
    "M4_incomplete_pass": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_incomplete_credentials_fail_closed_before_delivery",
    "M5_key_only_as_missing": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_key_only_credentials_fail_closed_before_delivery",
    "M6_id_only_as_missing": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_id_only_credentials_fail_closed_before_delivery",
    "M7_skip_merge_inverted": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_missing_app_run1_dispatches_validate_skips_merge_and_labels",
    "M8_app_token_switch_inverted": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_missing_app_run1_dispatches_validate_skips_merge_and_labels",
    "M9_fallback_branch_dropped": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_missing_app_run1_dispatches_validate_skips_merge_and_labels",
    "M10_dispatch_ref_main": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_missing_app_validate_dispatch_pins_exact_sha_on_pr_branch",
    "M11_expected_sha_fallback_dropped": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_missing_app_expected_sha_falls_back_to_sync_head",
    "M12_mint_if_dropped": "tests.test_cve_sync_workflow.CveSyncWorkflowTests.test_mint_and_attribute_steps_are_gated_on_app_configured",
    "M13_empty_app_token_guard_dropped": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_configured_app_empty_token_fails_closed",
    "M14_actions_permission_read": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_merge_job_actions_permission_is_write",
    "M15_fallback_label_dropped": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_missing_app_run1_dispatches_validate_skips_merge_and_labels",
    "M16_fallback_output_dropped": "tests.test_cve_sync_merge_harness.CveSyncMergeHarnessTests.test_missing_app_run1_dispatches_validate_skips_merge_and_labels",
}

SANDBOX_FILES = (
    ".github/workflows/cve-catalog-sync.yml",
    ".github/AUTOMATION.md",
    "README.md",
    "scripts/cve_catalog_delivery.py",
    "scripts/cve_catalog_data_paths.py",
    "tests/__init__.py",
    "tests/hermetic_network.py",
    "tests/cve_sync_harness.py",
    "tests/cve_sync_gh_stub.py",
    "tests/test_cve_sync_merge_harness.py",
    "tests/test_cve_sync_workflow.py",
    "tests/test_cve_catalog_delivery.py",
    "tests/cve_sync_mutants/__init__.py",
    "tests/cve_sync_mutants/mutants.py",
)
