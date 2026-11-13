#!/usr/bin/env python3
"""String-patch mutant kills. Not loaded by default unittest discover.

Run explicitly:

    python scripts/mutation_gate/test_mutant_kills.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.test_exact_sha_build_status_harness import (
    APP_ACTOR,
    APP_SLUG,
    CONTENT_BRANCH,
    FORTY_ONE_SHA,
    REGEX_WILDCARD_SLUG,
    SUBSTRING_BRANCH,
    assert_dedupe_skips_in_flight,
    assert_dispatch_carries_pr_head_sha,
    assert_existing_build_status_skips_dispatch,
    assert_failed_build_check_run_skips_dispatch,
    assert_invalid_format_slugs_refused,
    assert_killed,
    assert_non_build_check_run_does_not_skip_dispatch,
    assert_non_build_status_does_not_skip_dispatch,
    assert_non_catalog_pr_does_not_dispatch,
    assert_other_sha_inflight_does_not_block_head,
    assert_publish_gives_up_after_four_failures,
    assert_publish_job_wiring,
    assert_publish_maps_result,
    assert_publish_missing_sha_fails_closed,
    assert_publish_reads_named_pull,
    assert_publish_refuses_dispatch_origin,
    assert_publish_refuses_moved_head,
    assert_publish_refuses_non_catalog_branch,
    assert_publish_refuses_pull,
    assert_publish_refuses_result,
    assert_publish_retries_n_failures_then_posts,
    assert_shepherd_missing_sha_fails_closed,
    assert_shepherd_skips_cross_repository_sync_pr,
    assert_status_posted_to_head_sha_not_main,
    assert_sync_dispatch_accepted_on_main,
    assert_sync_validation_ref_is_main,
    live_pull,
)

class ExactShaBuildStatusMutantKillTests(unittest.TestCase):
    def test_M1_post_on_main_is_killed(self) -> None:
        assert_killed("M1-post-on-main", assert_status_posted_to_head_sha_not_main)

    def test_M2_drop_sha_input_is_killed(self) -> None:
        assert_killed("M2-drop-sha-input", assert_dispatch_carries_pr_head_sha)

    def test_M3_drop_dedupe_is_killed(self) -> None:
        assert_killed("M3-drop-dedupe", lambda paths: assert_dedupe_skips_in_flight(paths, "in_progress"))

    def test_M4_fail_open_missing_sha_is_killed(self) -> None:
        assert_killed("M4-fail-open-missing-sha", assert_publish_missing_sha_fails_closed)

    def test_M5_wrong_context_name_is_killed(self) -> None:
        assert_killed("M5-wrong-context-name", assert_status_posted_to_head_sha_not_main)

    def test_M6_shepherd_fail_open_missing_sha_is_killed(self) -> None:
        assert_killed("M6-shepherd-fail-open-missing-sha", lambda paths: assert_shepherd_missing_sha_fails_closed(paths, ""))

    def test_K1_null_head_z_guard_is_killed(self) -> None:
        assert_killed("K1-null-head-z-guard", lambda paths: assert_shepherd_missing_sha_fails_closed(paths, "null"))

    def test_K2_unanchored_sha_regex_is_killed(self) -> None:
        assert_killed("K2-unanchored-sha-regex", lambda paths: assert_shepherd_missing_sha_fails_closed(paths, FORTY_ONE_SHA))

    def test_K3_dedupe_without_sha_is_killed(self) -> None:
        assert_killed("K3-dedupe-without-sha", assert_other_sha_inflight_does_not_block_head)

    def test_K4_drop_queued_is_killed(self) -> None:
        assert_killed("K4-drop-queued", lambda paths: assert_dedupe_skips_in_flight(paths, "queued"))

    def test_K5_assign_not_accumulate_is_killed(self) -> None:
        assert_killed("K5-assign-not-accumulate", lambda paths: assert_dedupe_skips_in_flight(paths, "in_progress"))

    def test_K6_drop_statuses_or_is_killed(self) -> None:
        assert_killed("K6-drop-statuses-or", assert_existing_build_status_skips_dispatch)

    def test_K7_pending_gt_one_is_killed(self) -> None:
        assert_killed("K7-pending-gt-one", lambda paths: assert_dedupe_skips_in_flight(paths, "in_progress"))

    def test_K8_failure_posts_success_is_killed(self) -> None:
        assert_killed("K8-failure-posts-success", lambda paths: assert_publish_maps_result(paths, "failure", "failure"))

    def test_K9_cancelled_skipped_not_mapped_is_killed(self) -> None:
        assert_killed("K9-cancelled-skipped-unmapped", lambda paths: assert_publish_maps_result(paths, "cancelled", "failure"))

    def test_K10_unknown_posts_success_is_killed(self) -> None:
        assert_killed("K10-unknown-posts-success", lambda paths: assert_publish_refuses_result(paths, ""))

    def test_K11_drop_target_url_is_killed(self) -> None:
        assert_killed("K11-drop-target-url", assert_status_posted_to_head_sha_not_main)

    def test_K12_hardcoded_validate_result_is_killed(self) -> None:
        assert_killed("K12-hardcoded-validate-result", lambda paths: assert_publish_maps_result(paths, "failure", "failure"))

    def test_K13_expected_sha_from_github_sha_is_killed(self) -> None:
        assert_killed("K13-expected-sha-github-sha", assert_status_posted_to_head_sha_not_main)

    def test_K14_drop_always_is_killed(self) -> None:
        assert_killed("K14-drop-always", assert_publish_job_wiring)

    def test_K15_statuses_not_write_is_killed(self) -> None:
        assert_killed("K15-statuses-not-write", assert_publish_job_wiring)

    def test_K16_kick_without_publish_is_killed(self) -> None:
        assert_killed("K16-kick-without-publish", assert_publish_job_wiring)

    def test_K17_drop_catalog_sync_filter_is_killed(self) -> None:
        assert_killed("K17-drop-catalog-sync-filter", lambda paths: assert_non_catalog_pr_does_not_dispatch(paths, CONTENT_BRANCH))

    def test_K18_prefix_catalog_filter_is_killed(self) -> None:
        assert_killed("K18-prefix-catalog-filter", lambda paths: assert_non_catalog_pr_does_not_dispatch(paths, CONTENT_BRANCH))

    def test_K19_substring_catalog_filter_is_killed(self) -> None:
        assert_killed("K19-substring-catalog-filter", lambda paths: assert_non_catalog_pr_does_not_dispatch(paths, SUBSTRING_BRANCH))

    def test_K20_drop_live_head_check_is_killed(self) -> None:
        assert_killed("K20-drop-live-head-check", assert_publish_refuses_moved_head)

    def test_B1_c_pr_number_from_run_id_is_killed(self) -> None:
        assert_killed("B1-c-pr-number-from-run-id", assert_publish_reads_named_pull)

    def test_B1_e_pulls_path_wrong_pr_is_killed(self) -> None:
        assert_killed("B1-e-pulls-path-wrong-pr", assert_publish_reads_named_pull)

    def test_K6b_drop_check_runs_or_is_killed(self) -> None:
        assert_killed("B2-K6b-drop-checkruns-or", assert_failed_build_check_run_skips_dispatch)

    def test_K6c_status_any_context_is_killed(self) -> None:
        assert_killed("B2-K6c-status-any-context", assert_non_build_status_does_not_skip_dispatch)

    def test_K6d_checkrun_any_name_is_killed(self) -> None:
        assert_killed("B2-K6d-checkrun-any-name", assert_non_build_check_run_does_not_skip_dispatch)

    def test_P_c_fork_head_is_killed(self) -> None:
        assert_killed(
            "P-c-drop-head-repo-check",
            lambda paths: assert_publish_refuses_pull(
                paths, live_pull(repo={"full_name": "evil/security-recipes.ai"}), "a fork head"
            ),
        )

    def test_P_g_missing_head_repo_is_killed(self) -> None:
        assert_killed(
            "P-g-head-repo-default-self",
            lambda paths: assert_publish_refuses_pull(paths, live_pull(repo=None), "missing head repo"),
        )

    def test_P_d_closed_pr_is_killed(self) -> None:
        assert_killed(
            "P-d-drop-state-open",
            lambda paths: assert_publish_refuses_pull(paths, live_pull(state="closed"), "closed PR"),
        )

    def test_P_e_base_not_main_is_killed(self) -> None:
        assert_killed(
            "P-e-drop-base-check",
            lambda paths: assert_publish_refuses_pull(paths, live_pull(base="release"), "base=release"),
        )

    def test_S_d_cross_repo_is_killed(self) -> None:
        assert_killed("S-d-drop-crossrepo-select", assert_shepherd_skips_cross_repository_sync_pr)

    def test_R_b_max_2_is_killed(self) -> None:
        assert_killed("R-b-max-2", lambda paths: assert_publish_retries_n_failures_then_posts(paths, 3))

    def test_R_c_max_3_is_killed(self) -> None:
        assert_killed("R-c-max-3", lambda paths: assert_publish_retries_n_failures_then_posts(paths, 3))

    def test_R_d_max_5_is_killed(self) -> None:
        assert_killed("R-d-max-5", assert_publish_gives_up_after_four_failures)

    def test_R_e_ge_to_gt_is_killed(self) -> None:
        assert_killed("R-e-ge-to-gt", assert_publish_gives_up_after_four_failures)

    def test_S_a_suffix_filter_is_killed(self) -> None:
        assert_killed(
            "S-a-suffix-filter",
            lambda paths: assert_non_catalog_pr_does_not_dispatch(paths, "x/automation/cve-catalog-sync"),
        )

    def test_S_b_prefix_of_sync_is_killed(self) -> None:
        assert_killed(
            "S-b-prefix-of-sync",
            lambda paths: assert_non_catalog_pr_does_not_dispatch(paths, "automation/cve-catalog-sync-2"),
        )

    def test_P_i_prefix_of_sync_is_killed(self) -> None:
        assert_killed(
            "P-i-publish-prefix-of-sync-both",
            lambda paths: assert_publish_refuses_non_catalog_branch(paths, "automation/cve-catalog-sync-2"),
        )

    def test_D1_drop_ref_check_is_killed(self) -> None:
        assert_killed(
            "D1-drop-ref-check",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths, dispatch_ref="refs/heads/automation/cve-catalog-sync", why="non-main ref"
            ),
        )

    def test_D2_ref_prefix_is_killed(self) -> None:
        assert_killed(
            "D2-ref-prefix",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths, dispatch_ref="refs/heads/main-x", why="main-x ref"
            ),
        )

    def test_D3_drop_actor_check_is_killed(self) -> None:
        assert_killed(
            "D3-drop-actor-check",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths, dispatch_actor="evil-bot", why="wrong actor"
            ),
        )

    def test_D4_actor_substring_is_killed(self) -> None:
        assert_killed(
            "D4-actor-substring",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths, dispatch_actor="xgithub-actions[bot]", why="substring actor"
            ),
        )

    def test_D5_guard_exit_0_is_killed(self) -> None:
        assert_killed(
            "D5-guard-exit-0",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths, dispatch_ref="refs/heads/development", why="non-main ref"
            ),
        )

    def test_D2c_ref_suffix_main_is_killed(self) -> None:
        assert_killed(
            "D2c-ref-suffix-main",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths, dispatch_ref="refs/heads/x/main", why="refs/heads/x/main"
            ),
        )

    def test_F_lookalike_bot_is_killed(self) -> None:
        assert_killed(
            "F-lookalike-bot",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                dispatch_actor=f"{APP_SLUG}-x[bot]",
                app_slug=APP_SLUG,
                why="slug-x[bot]",
            ),
        )

    def test_F_any_bot_is_killed(self) -> None:
        assert_killed(
            "F-any-bot",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                dispatch_actor="dependabot[bot]",
                app_slug=APP_SLUG,
                why="dependabot[bot]",
            ),
        )

    def test_F_unset_accepts_app_is_killed(self) -> None:
        assert_killed(
            "F-unset-accepts-app",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                dispatch_actor=APP_ACTOR,
                why="App actor with unset slug",
            ),
        )

    def test_F_app_on_non_main_is_killed(self) -> None:
        assert_killed(
            "F-app-on-non-main",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                dispatch_ref="refs/heads/x/main",
                dispatch_actor=APP_ACTOR,
                app_slug=APP_SLUG,
                why="App actor on refs/heads/x/main",
            ),
        )

    def test_F_loosened_slug_is_killed(self) -> None:
        assert_killed(
            "F-loosened-slug",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                dispatch_actor=f"x{APP_SLUG}[bot]",
                app_slug=APP_SLUG,
                why="xslug[bot]",
            ),
        )

    def test_A6_case_insensitive_app_actor_is_killed(self) -> None:
        assert_killed(
            "A6-case-insensitive-app-actor",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                dispatch_actor="QA-CVE-SYNC[bot]",
                app_slug=APP_SLUG,
                why="QA-CVE-SYNC[bot]",
            ),
        )

    def test_I2_regex_app_actor_is_killed(self) -> None:
        assert_killed(
            "I2-regex-app-actor",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                dispatch_actor=f"{APP_SLUG}b",
                app_slug=APP_SLUG,
                why="qa-cve-syncb against regex [bot] character class",
            ),
        )

    def test_I2_bad_slug_ignored_is_killed(self) -> None:
        assert_killed(
            "I2-bad-slug-ignored",
            lambda paths: assert_publish_refuses_dispatch_origin(
                paths,
                app_slug=REGEX_WILDCARD_SLUG,
                why="invalid slug ignored",
            ),
        )

    def test_V_restore_pr_branch_validation_ref_is_killed(self) -> None:
        assert_killed("V-restore-pr-branch-validation-ref", assert_sync_validation_ref_is_main)

    def test_R1a_sync_ref_branch_is_killed(self) -> None:
        assert_killed(
            "R1a-sync-ref-branch",
            lambda paths: assert_sync_dispatch_accepted_on_main(paths, app_path=True),
        )

    def test_R1b_default_branch_branch_is_killed(self) -> None:
        assert_killed(
            "R1b-default-branch-branch",
            lambda paths: assert_sync_dispatch_accepted_on_main(paths, app_path=False),
        )

    def test_R2a_delivery_github_token_is_killed(self) -> None:
        assert_killed(
            "R2a-delivery-github-token",
            lambda paths: assert_sync_dispatch_accepted_on_main(paths, app_path=True),
        )

    def test_SF2_drop_start_anchor_is_killed(self) -> None:
        assert_killed("SF2-drop-start-anchor", assert_invalid_format_slugs_refused)

    def test_SF3_drop_end_anchor_is_killed(self) -> None:
        assert_killed("SF3-drop-end-anchor", assert_invalid_format_slugs_refused)

    def test_SF4_allow_dot_is_killed(self) -> None:
        assert_killed("SF4-allow-dot", assert_invalid_format_slugs_refused)

    def test_SF5_allow_uppercase_is_killed(self) -> None:
        assert_killed("SF5-allow-uppercase", assert_invalid_format_slugs_refused)


if __name__ == "__main__":
    unittest.main()
