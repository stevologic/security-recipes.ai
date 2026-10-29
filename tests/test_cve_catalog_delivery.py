from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

from scripts.cve_catalog_data_paths import (
    catalog_data_blob_map,
    catalog_revision_content_matches,
    candidate_parent_diffs_are_data_only,
    commit_parent_shas,
    is_catalog_data_path,
)
from scripts.cve_catalog_delivery import (
    FALLBACK_LABEL,
    GENERATED_OUTPUT_BRANCH,
    KAREN_QA_REVIEW_LABEL,
    WRONG_SHA_CHECKPOINTS,
    can_reuse_in_run_validation,
    classify_generated_output_review,
    classify_merge_error,
    classify_pr_state,
    classify_protection_fallback,
    fail_closed_merged_wrong_sha,
    is_alert_action,
    main as delivery_main,
    merged_revision_matches,
    merged_sha_matches,
    policy_for_catalog_pr,
    self_merge_gate,
    validation_ref,
)


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "cve-catalog-sync.yml"
AUTOMATION = ROOT / ".github" / "AUTOMATION.md"

SHA = "0a7e0100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
OTHER = "cccccccccccccccccccccccccccccccccccccccc"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _init_catalog_repo(repo: Path) -> None:
    _git(repo, "init")
    _git(repo, "config", "user.email", "catalog-bot@example.test")
    _git(repo, "config", "user.name", "catalog-bot")
    _git(repo, "checkout", "-b", "main")


def _write_catalog(repo: Path, *, body: str, note: str = "") -> None:
    catalog = repo / "static" / "api" / "cve-catalog"
    catalog.mkdir(parents=True, exist_ok=True)
    (catalog / "manifest.json").write_text(body, encoding="utf-8")
    data = repo / "data" / "cve"
    data.mkdir(parents=True, exist_ok=True)
    (data / "ai-enrichments.json").write_text("{}\n", encoding="utf-8")
    (data / "ai-generated-recipes.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generator": "cve-ai-enrichment-v1",
                "entries": {},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    if note:
        (repo / "README").write_text(note, encoding="utf-8")


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


def _empty_commit(repo: Path, message: str) -> str:
    _git(repo, "commit", "--allow-empty", "-m", message)
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


def _commit_tree(repo: Path, message: str, *parents: str) -> str:
    tree = _git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    args = ["commit-tree", tree]
    for parent in parents:
        args.extend(["-p", parent])
    args.extend(["-m", message])
    return _git(repo, *args).stdout.strip()


def pr_payload(
    *,
    state: str = "open",
    merged: bool = False,
    head_sha: str = SHA,
    head_branch: str = "automation/cve-catalog-sync",
    base_branch: str = "main",
    repo: str = "stevologic/security-recipes.ai",
    merge_commit_sha: str = "",
) -> dict[str, object]:
    return {
        "state": state,
        "merged": merged,
        "merge_commit_sha": merge_commit_sha,
        "head": {"sha": head_sha, "ref": head_branch, "repo": {"full_name": repo}},
        "base": {"ref": base_branch},
    }


class CveCatalogDeliveryTests(unittest.TestCase):
    def test_data_only_policy_skips_karen_qa_and_allows_token_merge(self) -> None:
        policy = policy_for_catalog_pr(data_only=True, sha_matches=True, app_configured=False)
        self.assertTrue(policy.skip_karen_qa)
        self.assertTrue(policy.attach_build_check_on_pr_head)
        self.assertTrue(policy.protection_fallback)
        self.assertTrue(policy.merge_with_workflow_token)
        self.assertEqual(policy.action, "validate_and_merge")
        self.assertFalse(is_alert_action(policy.action))

    def test_data_only_with_app_still_skips_karen_qa(self) -> None:
        policy = policy_for_catalog_pr(data_only=True, sha_matches=True, app_configured=True)
        self.assertTrue(policy.skip_karen_qa)
        self.assertFalse(policy.attach_build_check_on_pr_head)
        self.assertTrue(policy.protection_fallback)

    def test_non_data_only_fails_closed(self) -> None:
        policy = policy_for_catalog_pr(data_only=False, sha_matches=True, app_configured=False)
        self.assertEqual(policy.action, "fail_closed_not_data_only")
        self.assertFalse(policy.skip_karen_qa)
        self.assertFalse(policy.protection_fallback)
        self.assertTrue(is_alert_action(policy.action))
        self.assertIn("karen-qa and real workflow checks", policy.message)

    def test_sha_mismatch_fails_closed(self) -> None:
        policy = policy_for_catalog_pr(data_only=True, sha_matches=False, app_configured=False)
        self.assertEqual(policy.action, "fail_closed_sha_mismatch")
        self.assertTrue(is_alert_action(policy.action))

    def test_already_merged_pr_is_idempotent_success(self) -> None:
        action = classify_pr_state(
            state="closed",
            merged=True,
            head_repository="stevologic/security-recipes.ai",
            head_branch="automation/cve-catalog-sync",
            head_sha=SHA,
            base_branch="main",
            expected_repository="stevologic/security-recipes.ai",
            expected_branch="automation/cve-catalog-sync",
            expected_sha=SHA,
            expected_base="main",
        )
        self.assertEqual(action, "already_merged")
        self.assertFalse(is_alert_action(action))

    def test_merged_at_a_different_head_is_a_real_error(self) -> None:
        action = classify_pr_state(
            state="closed",
            merged=True,
            head_repository="stevologic/security-recipes.ai",
            head_branch="automation/cve-catalog-sync",
            head_sha=OTHER,
            base_branch="main",
            expected_repository="stevologic/security-recipes.ai",
            expected_branch="automation/cve-catalog-sync",
            expected_sha=SHA,
            expected_base="main",
            merge_commit_sha=OTHER,
        )
        self.assertEqual(action, "merged_wrong_sha")
        self.assertTrue(is_alert_action(action))
        self.assertFalse(merged_sha_matches(head_sha=OTHER, merge_commit_sha=OTHER, expected_sha=SHA))

    def test_merged_at_expected_merge_commit_sha_is_idempotent(self) -> None:
        action = classify_pr_state(
            state="closed",
            merged=True,
            head_repository="stevologic/security-recipes.ai",
            head_branch="automation/cve-catalog-sync",
            head_sha=OTHER,
            base_branch="main",
            expected_repository="stevologic/security-recipes.ai",
            expected_branch="automation/cve-catalog-sync",
            expected_sha=SHA,
            expected_base="main",
            merge_commit_sha=SHA,
        )
        self.assertEqual(action, "already_merged")
        self.assertFalse(is_alert_action(action))
        self.assertTrue(merged_sha_matches(head_sha=OTHER, merge_commit_sha=SHA, expected_sha=SHA))

    def test_merged_squash_sha_with_identical_catalog_content_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            _init_catalog_repo(repo)
            _write_catalog(repo, body='{"revision":"expected"}\n')
            _commit(repo, "base")
            _write_catalog(repo, body='{"revision":"catalog"}\n')
            expected = _commit(repo, "catalog head")
            squash = _empty_commit(repo, "squash onto a moved main")
            self.assertNotEqual(expected, squash)
            self.assertTrue(
                merged_revision_matches(
                    head_sha=squash,
                    merge_commit_sha=squash,
                    expected_sha=expected,
                    repo=repo,
                )
            )
            action = classify_pr_state(
                state="closed",
                merged=True,
                head_repository="stevologic/security-recipes.ai",
                head_branch="automation/cve-catalog-sync",
                head_sha=squash,
                base_branch="main",
                expected_repository="stevologic/security-recipes.ai",
                expected_branch="automation/cve-catalog-sync",
                expected_sha=expected,
                expected_base="main",
                merge_commit_sha=squash,
                repo=repo,
            )
            self.assertEqual(action, "already_merged")
            self.assertFalse(is_alert_action(action))

    def test_merged_merge_commit_sha_with_identical_catalog_content_is_idempotent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            _init_catalog_repo(repo)
            _write_catalog(repo, body='{"revision":"base"}\n', note="shared\n")
            (repo / "docs.txt").write_text("unrelated shared file\n", encoding="utf-8")
            base = _commit(repo, "shared base")
            _write_catalog(repo, body='{"revision":"catalog"}\n', note="shared\n")
            expected = _commit(repo, "catalog head")
            _git(repo, "checkout", "-B", "main-line", base)
            _git(repo, "merge", "--no-ff", "-m", "merge catalog", expected)
            merge_sha = _git(repo, "rev-parse", "HEAD").stdout.strip()
            self.assertNotEqual(expected, merge_sha)
            action = classify_pr_state(
                state="closed",
                merged=True,
                head_repository="stevologic/security-recipes.ai",
                head_branch="automation/cve-catalog-sync",
                head_sha=expected,
                base_branch="main",
                expected_repository="stevologic/security-recipes.ai",
                expected_branch="automation/cve-catalog-sync",
                expected_sha=expected,
                expected_base="main",
                merge_commit_sha=merge_sha,
                repo=repo,
            )
            self.assertEqual(action, "already_merged")
            self.assertFalse(is_alert_action(action))
            self.assertTrue(
                merged_revision_matches(
                    head_sha=OTHER,
                    merge_commit_sha=merge_sha,
                    expected_sha=expected,
                    repo=repo,
                )
            )

    def test_merged_squash_sha_with_different_catalog_content_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            _init_catalog_repo(repo)
            _write_catalog(repo, body='{"revision":"expected"}\n')
            expected = _commit(repo, "catalog head")
            _write_catalog(repo, body='{"revision":"tampered"}\n')
            squash = _commit(repo, "squash with different catalog")
            self.assertFalse(
                merged_revision_matches(
                    head_sha=squash,
                    merge_commit_sha=squash,
                    expected_sha=expected,
                    repo=repo,
                )
            )
            action = classify_pr_state(
                state="closed",
                merged=True,
                head_repository="stevologic/security-recipes.ai",
                head_branch="automation/cve-catalog-sync",
                head_sha=squash,
                base_branch="main",
                expected_repository="stevologic/security-recipes.ai",
                expected_branch="automation/cve-catalog-sync",
                expected_sha=expected,
                expected_base="main",
                merge_commit_sha=squash,
                repo=repo,
            )
            self.assertEqual(action, "merged_wrong_sha")
            self.assertTrue(is_alert_action(action))

    def test_pr_state_cli_accepts_merged_content_match_and_rejects_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            _init_catalog_repo(repo)
            _write_catalog(repo, body='{"revision":"catalog"}\n')
            _commit(repo, "base")
            expected = _empty_commit(repo, "catalog head")
            squash = _empty_commit(repo, "squash same catalog")
            match_path = repo / "match.json"
            match_path.write_text(
                json.dumps(
                    pr_payload(
                        merged=True,
                        state="closed",
                        head_sha=squash,
                        merge_commit_sha=squash,
                    )
                ),
                encoding="utf-8",
            )
            mismatch_path = repo / "mismatch.json"
            _write_catalog(repo, body='{"revision":"other"}\n', note="moved\n")
            other = _commit(repo, "different catalog")
            mismatch_path.write_text(
                json.dumps(
                    pr_payload(
                        merged=True,
                        state="closed",
                        head_sha=other,
                        merge_commit_sha=other,
                    )
                ),
                encoding="utf-8",
            )
            previous = Path.cwd()
            try:
                os.chdir(repo)
                match_out = StringIO()
                with redirect_stdout(match_out):
                    self.assertEqual(
                        delivery_main(
                            [
                                "pr-state",
                                "--pr-json-file",
                                str(match_path),
                                "--expected-repository",
                                "stevologic/security-recipes.ai",
                                "--expected-branch",
                                "automation/cve-catalog-sync",
                                "--expected-sha",
                                expected,
                                "--expected-base",
                                "main",
                            ]
                        ),
                        0,
                    )
                self.assertEqual(match_out.getvalue().strip(), "already_merged")
                mismatch_out = StringIO()
                with redirect_stdout(mismatch_out):
                    self.assertEqual(
                        delivery_main(
                            [
                                "pr-state",
                                "--pr-json-file",
                                str(mismatch_path),
                                "--expected-repository",
                                "stevologic/security-recipes.ai",
                                "--expected-branch",
                                "automation/cve-catalog-sync",
                                "--expected-sha",
                                expected,
                                "--expected-base",
                                "main",
                            ]
                        ),
                        0,
                    )
                self.assertEqual(mismatch_out.getvalue().strip(), "merged_wrong_sha")
            finally:
                os.chdir(previous)

    def test_empty_catalog_maps_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            _init_catalog_repo(repo)
            (repo / "README").write_text("no catalog\n", encoding="utf-8")
            empty = _commit(repo, "empty tree")
            self.assertEqual(catalog_data_blob_map(empty, repo=repo), {})
            self.assertFalse(
                catalog_revision_content_matches(
                    expected_sha=empty,
                    candidate_shas=(empty,),
                    repo=repo,
                )
            )
            self.assertFalse(
                merged_revision_matches(
                    head_sha=OTHER,
                    merge_commit_sha=OTHER,
                    expected_sha=empty,
                    repo=repo,
                )
            )

    def test_blob_map_equality_rejects_subset_and_superset(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            _init_catalog_repo(repo)
            _write_catalog(repo, body='{"revision":"core"}\n')
            core = _commit(repo, "core catalog")
            extra = repo / "static" / "api" / "cve-catalog" / "extra.json"
            extra.write_text('{"extra":true}\n', encoding="utf-8")
            superset = _commit(repo, "core plus extra shard")
            self.assertNotEqual(
                catalog_data_blob_map(core, repo=repo),
                catalog_data_blob_map(superset, repo=repo),
            )
            self.assertFalse(
                catalog_revision_content_matches(
                    expected_sha=core,
                    candidate_shas=(superset,),
                    repo=repo,
                )
            )
            self.assertFalse(
                catalog_revision_content_matches(
                    expected_sha=superset,
                    candidate_shas=(core,),
                    repo=repo,
                )
            )

    def test_symlink_or_non_regular_catalog_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            _init_catalog_repo(repo)
            _write_catalog(repo, body='{"revision":"catalog"}\n')
            expected = _commit(repo, "regular catalog")
            manifest = repo / "static" / "api" / "cve-catalog" / "manifest.json"
            manifest.unlink()
            manifest.symlink_to("elsewhere")
            linked = _commit(repo, "symlink catalog")
            self.assertIsNone(catalog_data_blob_map(linked, repo=repo))
            self.assertFalse(
                catalog_revision_content_matches(
                    expected_sha=expected,
                    candidate_shas=(linked,),
                    repo=repo,
                )
            )
            _git(repo, "checkout", "-B", "mode", expected)
            executable = repo / "data" / "cve" / "ai-enrichments.json"
            executable.chmod(0o755)
            _git(repo, "add", "--chmod=+x", "data/cve/ai-enrichments.json")
            _git(repo, "commit", "-m", "executable catalog file")
            mode_changed = _git(repo, "rev-parse", "HEAD").stdout.strip()
            self.assertIsNone(catalog_data_blob_map(mode_changed, repo=repo))
            self.assertFalse(
                catalog_revision_content_matches(
                    expected_sha=expected,
                    candidate_shas=(mode_changed,),
                    repo=repo,
                )
            )

    def test_unreadable_or_missing_commits_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            _init_catalog_repo(repo)
            _write_catalog(repo, body='{"revision":"catalog"}\n')
            expected = _commit(repo, "catalog head")
            missing = "0" * 40
            unread = "f" * 40
            self.assertFalse(
                catalog_revision_content_matches(
                    expected_sha=missing,
                    candidate_shas=(expected,),
                    repo=repo,
                )
            )
            self.assertFalse(
                catalog_revision_content_matches(
                    expected_sha=expected,
                    candidate_shas=(unread, missing),
                    repo=repo,
                )
            )
            self.assertFalse(
                merged_revision_matches(
                    head_sha=unread,
                    merge_commit_sha=missing,
                    expected_sha=expected,
                    repo=repo,
                )
            )

    def test_blob_map_filters_non_allowlisted_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            _init_catalog_repo(repo)
            _write_catalog(repo, body='{"revision":"catalog"}\n')
            recipes = repo / "content" / "recipes" / "cve"
            recipes.mkdir(parents=True, exist_ok=True)
            (recipes / "ok.md").write_text("recipe\n", encoding="utf-8")
            (recipes / "evil.py").write_text("print(1)\n", encoding="utf-8")
            commit = _commit(repo, "allowlisted recipe plus evil.py")
            mapping = catalog_data_blob_map(commit, repo=repo)
            self.assertIsNotNone(mapping)
            assert mapping is not None
            self.assertIn("content/recipes/cve/ok.md", mapping)
            self.assertNotIn("content/recipes/cve/evil.py", mapping)
            self.assertTrue(all(is_catalog_data_path(path) for path in mapping))

    def test_explicit_content_matches_false_fails_closed(self) -> None:
        self.assertFalse(
            merged_revision_matches(
                head_sha=OTHER,
                merge_commit_sha=OTHER,
                expected_sha=SHA,
                content_matches=False,
            )
        )
        self.assertEqual(
            classify_pr_state(
                state="closed",
                merged=True,
                head_repository="stevologic/security-recipes.ai",
                head_branch="automation/cve-catalog-sync",
                head_sha=OTHER,
                base_branch="main",
                expected_repository="stevologic/security-recipes.ai",
                expected_branch="automation/cve-catalog-sync",
                expected_sha=SHA,
                expected_base="main",
                merge_commit_sha=OTHER,
                content_matches=False,
            ),
            "merged_wrong_sha",
        )

    def test_same_catalog_plus_workflow_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            _init_catalog_repo(repo)
            _write_catalog(repo, body='{"revision":"catalog"}\n')
            expected = _commit(repo, "catalog head")
            workflow = repo / ".github" / "workflows"
            workflow.mkdir(parents=True)
            (workflow / "x.yml").write_text("name: pwn\n", encoding="utf-8")
            attacked = _commit(repo, "same catalog plus workflow")
            self.assertEqual(
                catalog_data_blob_map(expected, repo=repo),
                catalog_data_blob_map(attacked, repo=repo),
            )
            self.assertFalse(candidate_parent_diffs_are_data_only(attacked, repo=repo))
            self.assertFalse(
                catalog_revision_content_matches(
                    expected_sha=expected,
                    candidate_shas=(attacked,),
                    repo=repo,
                )
            )
            self.assertFalse(
                merged_revision_matches(
                    head_sha=attacked,
                    merge_commit_sha=attacked,
                    expected_sha=expected,
                    repo=repo,
                )
            )

    def test_more_than_two_parents_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            _init_catalog_repo(repo)
            _write_catalog(repo, body='{"revision":"catalog"}\n')
            expected = _commit(repo, "catalog head")
            second = _empty_commit(repo, "second parent")
            third = _empty_commit(repo, "third parent")
            octopus = _commit_tree(repo, "octopus", expected, second, third)
            self.assertEqual(len(commit_parent_shas(octopus, repo=repo) or ()), 3)
            self.assertFalse(candidate_parent_diffs_are_data_only(octopus, repo=repo))
            self.assertEqual(
                catalog_data_blob_map(expected, repo=repo),
                catalog_data_blob_map(octopus, repo=repo),
            )
            self.assertFalse(
                catalog_revision_content_matches(
                    expected_sha=expected,
                    candidate_shas=(octopus,),
                    repo=repo,
                )
            )

    def test_moved_head_retries_instead_of_alerting(self) -> None:
        action = classify_pr_state(
            state="open",
            merged=False,
            head_repository="stevologic/security-recipes.ai",
            head_branch="automation/cve-catalog-sync",
            head_sha=OTHER,
            base_branch="main",
            expected_repository="stevologic/security-recipes.ai",
            expected_branch="automation/cve-catalog-sync",
            expected_sha=SHA,
            expected_base="main",
        )
        self.assertEqual(action, "head_moved")
        self.assertFalse(is_alert_action(action))

    def test_existing_open_pr_at_expected_sha_is_current(self) -> None:
        action = classify_pr_state(
            state="open",
            merged=False,
            head_repository="stevologic/security-recipes.ai",
            head_branch="automation/cve-catalog-sync",
            head_sha=SHA,
            base_branch="main",
            expected_repository="stevologic/security-recipes.ai",
            expected_branch="automation/cve-catalog-sync",
            expected_sha=SHA,
            expected_base="main",
        )
        self.assertEqual(action, "current")

    def test_identity_change_fails_closed(self) -> None:
        action = classify_pr_state(
            state="open",
            merged=False,
            head_repository="evil/fork",
            head_branch="automation/cve-catalog-sync",
            head_sha=SHA,
            base_branch="main",
            expected_repository="stevologic/security-recipes.ai",
            expected_branch="automation/cve-catalog-sync",
            expected_sha=SHA,
            expected_base="main",
        )
        self.assertEqual(action, "identity_changed")
        self.assertTrue(is_alert_action(action))

    def test_revalidated_sha_reuses_only_this_run_validation(self) -> None:
        self.assertTrue(
            can_reuse_in_run_validation(
                in_run_validation_passed=True,
                validated_sha=SHA,
                expected_sha=SHA,
            )
        )
        self.assertFalse(
            can_reuse_in_run_validation(
                in_run_validation_passed=True,
                validated_sha=SHA,
                expected_sha=OTHER,
            )
        )
        self.assertFalse(
            can_reuse_in_run_validation(
                in_run_validation_passed=False,
                validated_sha=SHA,
                expected_sha=SHA,
            )
        )

    def test_author_only_match_with_non_data_path_fails_closed(self) -> None:
        gate = self_merge_gate(
            data_only=False,
            sha_matches=True,
            in_run_validation_passed=True,
            validated_sha=SHA,
            head_branch="automation/cve-catalog-sync",
            head_sha=SHA,
            pushed_sha=SHA,
            sync_branch="automation/cve-catalog-sync",
            author="github-actions[bot]",
        )
        self.assertFalse(gate.allowed)
        self.assertFalse(gate.used_author)
        self.assertEqual(gate.action, "fail_closed_not_data_only")
        self.assertTrue(is_alert_action(gate.action))
        self.assertIn("author identity is ignored", gate.message)

    def test_self_merge_requires_in_run_validation_and_pushed_sha(self) -> None:
        allowed = self_merge_gate(
            data_only=True,
            sha_matches=True,
            in_run_validation_passed=True,
            validated_sha=SHA,
            head_branch="automation/cve-catalog-sync",
            head_sha=SHA,
            pushed_sha=SHA,
            sync_branch="automation/cve-catalog-sync",
            author="github-actions[bot]",
        )
        self.assertTrue(allowed.allowed)
        self.assertFalse(allowed.used_author)
        missing_validation = self_merge_gate(
            data_only=True,
            sha_matches=True,
            in_run_validation_passed=False,
            validated_sha="",
            head_branch="automation/cve-catalog-sync",
            head_sha=SHA,
            pushed_sha=SHA,
            sync_branch="automation/cve-catalog-sync",
            author="github-actions[bot]",
        )
        self.assertFalse(missing_validation.allowed)
        self.assertEqual(missing_validation.action, "fail_closed_missing_in_run_validation")
        moved = self_merge_gate(
            data_only=True,
            sha_matches=True,
            in_run_validation_passed=True,
            validated_sha=SHA,
            head_branch="automation/cve-catalog-sync",
            head_sha=OTHER,
            pushed_sha=SHA,
            sync_branch="automation/cve-catalog-sync",
            author="github-actions[bot]",
        )
        self.assertFalse(moved.allowed)
        self.assertEqual(moved.action, "fail_closed_head_mismatch")

    def test_data_only_without_app_dispatches_validation_on_pr_head(self) -> None:
        self.assertEqual(
            validation_ref(
                data_only=True,
                app_configured=False,
                default_branch="main",
                pr_branch="automation/cve-catalog-sync",
            ),
            "automation/cve-catalog-sync",
        )
        self.assertEqual(
            validation_ref(
                data_only=True,
                app_configured=True,
                default_branch="main",
                pr_branch="automation/cve-catalog-sync",
            ),
            "main",
        )

    def test_protection_block_on_data_only_is_fallback_not_alert(self) -> None:
        action = classify_merge_error(
            data_only=True,
            error_text="Required status check 'build' is expected and failed rule violations",
        )
        self.assertEqual(action, "protection_fallback")
        self.assertFalse(is_alert_action(action))
        karen = classify_merge_error(
            data_only=True,
            error_text="Required status check karen-qa is expected",
        )
        self.assertEqual(karen, "protection_fallback")
        self.assertFalse(is_alert_action(karen))

    def test_protection_block_on_non_data_only_fails_closed(self) -> None:
        action = classify_merge_error(
            data_only=False,
            error_text="Required status check 'build' is expected; required checks must come from real workflow runs",
        )
        self.assertEqual(action, "fail_closed_real_checks")
        self.assertTrue(is_alert_action(action))
        karen = classify_merge_error(data_only=False, error_text="needs karen-qa")
        self.assertEqual(karen, "wait_karen_qa")
        self.assertFalse(is_alert_action(karen))

    def test_unexpected_merge_error_alerts(self) -> None:
        action = classify_merge_error(data_only=True, error_text="HTTP 500 boom")
        self.assertEqual(action, "fail_unexpected")
        self.assertTrue(is_alert_action(action))

    def test_pr_state_cli_reads_json_file_for_existing_and_merged_prs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "pr.json"
            path.write_text(json.dumps(pr_payload(merged=True, state="closed")), encoding="utf-8")
            merged_out = StringIO()
            with redirect_stdout(merged_out):
                self.assertEqual(
                    delivery_main(
                        [
                            "pr-state",
                            "--pr-json-file",
                            str(path),
                            "--expected-repository",
                            "stevologic/security-recipes.ai",
                            "--expected-branch",
                            "automation/cve-catalog-sync",
                            "--expected-sha",
                            SHA,
                            "--expected-base",
                            "main",
                        ]
                    ),
                    0,
                )
            self.assertEqual(merged_out.getvalue().strip(), "already_merged")
            wrong = Path(tmpdir) / "wrong.json"
            wrong.write_text(
                json.dumps(pr_payload(merged=True, state="closed", head_sha=OTHER, merge_commit_sha=OTHER)),
                encoding="utf-8",
            )
            stdout = StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(
                    delivery_main(
                        [
                            "pr-state",
                            "--pr-json-file",
                            str(wrong),
                            "--expected-repository",
                            "stevologic/security-recipes.ai",
                            "--expected-branch",
                            "automation/cve-catalog-sync",
                            "--expected-sha",
                            SHA,
                            "--expected-base",
                            "main",
                        ]
                    ),
                    0,
                )
            self.assertEqual(stdout.getvalue().strip(), "merged_wrong_sha")

    def test_fallback_escalates_on_second_consecutive_run(self) -> None:
        now = datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc)
        first = classify_protection_fallback(
            already_labeled=False,
            labeled_at="",
            now=now,
        )
        self.assertFalse(first.escalate)
        self.assertEqual(first.action, "protection_fallback")
        self.assertFalse(is_alert_action(first.action))
        second = classify_protection_fallback(
            already_labeled=True,
            labeled_at="2026-10-27T07:00:00Z",
            now=now,
        )
        self.assertTrue(second.escalate)
        self.assertEqual(second.action, "fail_fallback_escalated")
        self.assertTrue(is_alert_action(second.action))
        self.assertIn("2 consecutive", second.message)
        self.assertIn("GitHub App is not configured", second.message)
        self.assertIn("CVE_SYNC_APP_ID", second.message)
        self.assertIn("CVE_SYNC_APP_KEY", second.message)
        configured = classify_protection_fallback(
            already_labeled=True,
            labeled_at="2026-10-27T07:00:00Z",
            now=now,
            app_configured=True,
        )
        self.assertTrue(configured.escalate)
        self.assertNotIn("GitHub App is not configured", configured.message)

    def test_fallback_escalates_when_label_is_older_than_24h(self) -> None:
        now = datetime(2026, 10, 28, 8, 30, tzinfo=timezone.utc)
        decision = classify_protection_fallback(
            already_labeled=False,
            labeled_at=(now - timedelta(hours=24, minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            now=now,
        )
        self.assertTrue(decision.escalate)
        self.assertEqual(decision.action, "fail_fallback_escalated")
        self.assertTrue(is_alert_action(decision.action))
        self.assertIn("label is older than 24h", decision.message)
        self.assertIn("GitHub App is not configured", decision.message)

    def test_fallback_does_not_use_pr_created_at_for_24h(self) -> None:
        now = datetime(2026, 10, 28, 8, 30, tzinfo=timezone.utc)
        first_on_old_pr = classify_protection_fallback(
            already_labeled=False,
            labeled_at="",
            now=now,
        )
        self.assertFalse(first_on_old_pr.escalate)
        self.assertEqual(first_on_old_pr.age_hours, 0.0)

    def test_each_wrong_sha_checkpoint_exits_one(self) -> None:
        self.assertEqual(
            WRONG_SHA_CHECKPOINTS,
            ("before_validation", "after_validation", "after_merge_attempt"),
        )
        for checkpoint in WRONG_SHA_CHECKPOINTS:
            with self.subTest(checkpoint=checkpoint):
                with redirect_stderr(StringIO()):
                    self.assertEqual(
                        fail_closed_merged_wrong_sha(
                            checkpoint=checkpoint,
                            pr_state="merged_wrong_sha",
                        ),
                        1,
                    )
                    self.assertEqual(
                        fail_closed_merged_wrong_sha(
                            checkpoint=checkpoint,
                            pr_state="current",
                        ),
                        0,
                    )
                    self.assertEqual(
                        fail_closed_merged_wrong_sha(
                            checkpoint=checkpoint,
                            pr_state="already_merged",
                        ),
                        0,
                    )
                    stdout = StringIO()
                    with redirect_stdout(stdout):
                        self.assertEqual(
                            delivery_main(
                                [
                                    "fail-closed-wrong-sha",
                                    "--checkpoint",
                                    checkpoint,
                                    "--pr-state",
                                    "merged_wrong_sha",
                                ]
                            ),
                            1,
                        )
                        self.assertEqual(
                            delivery_main(
                                [
                                    "fail-closed-wrong-sha",
                                    "--checkpoint",
                                    checkpoint,
                                    "--pr-state",
                                    "current",
                                ]
                            ),
                            0,
                        )

    def test_unknown_wrong_sha_checkpoint_fails_closed(self) -> None:
        with redirect_stderr(StringIO()):
            self.assertEqual(
                fail_closed_merged_wrong_sha(
                    checkpoint="not-a-phase",
                    pr_state="current",
                ),
                1,
            )

    def test_generated_output_review_failure_is_an_alert(self) -> None:
        ok = classify_generated_output_review(step_failed=False)
        self.assertFalse(ok.failed)
        self.assertFalse(ok.escalate)
        self.assertFalse(is_alert_action(ok.action))
        self.assertEqual(ok.exit_code(), 0)
        failed = classify_generated_output_review(step_failed=True)
        self.assertTrue(failed.failed)
        self.assertTrue(failed.escalate)
        self.assertEqual(failed.action, "fail_generated_output_review")
        self.assertTrue(is_alert_action(failed.action))
        self.assertEqual(failed.exit_code(), 1)
        self.assertIn("real alert", failed.message)
        failed_out = StringIO()
        with redirect_stdout(failed_out):
            self.assertEqual(
                delivery_main(["generated-output-review", "--step-failed", "true"]),
                1,
            )
        payload = json.loads(failed_out.getvalue())
        self.assertEqual(payload["action"], "fail_generated_output_review")
        ok_out = StringIO()
        with redirect_stdout(ok_out):
            self.assertEqual(
                delivery_main(["generated-output-review", "--step-failed", "false"]),
                0,
            )
        self.assertEqual(json.loads(ok_out.getvalue())["action"], "generated_output_ok")

    def test_workflow_wires_fallback_label_concurrency_and_build_dispatch_on_pr_head(
        self,
    ) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(FALLBACK_LABEL, workflow)
        self.assertIn("group: cve-catalog-sync", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("scripts/cve_catalog_data_paths.py", workflow)
        self.assertIn("scripts/cve_catalog_delivery.py", workflow)
        self.assertIn('--ref "$VALIDATION_REF"', workflow)
        self.assertIn("self-merge-gate", workflow)
        self.assertIn("reuse-in-run-validation", workflow)
        self.assertIn("Never gate self-merge on github-actions[bot]", workflow)
        self.assertNotIn("reuse-build-check", workflow)
        self.assertIn("protection_fallback=true", workflow)
        self.assertIn("fallback-escalation", workflow)
        self.assertIn("fail-closed-wrong-sha", workflow)
        self.assertIn("data/cve/enrichment-carryover.json", workflow)
        self.assertIn(GENERATED_OUTPUT_BRANCH, workflow)
        self.assertIn(KAREN_QA_REVIEW_LABEL, workflow)
        self.assertIn("continue-on-error: true", workflow)
        self.assertIn("--labeled-at", workflow)
        self.assertIn("issues/${PR_NUMBER}/events", workflow)
        self.assertNotIn("--created-at", workflow)
        self.assertIn("CVE catalog PR is unaffected", workflow)
        self.assertIn("generated-output-review --step-failed true", workflow)
        self.assertIn("Alert generated-output review PR failure", workflow)
        self.assertNotIn("Note generated-output review PR failure", workflow)
        self.assertNotIn('if [ "$PR_STATE" = "merged_wrong_sha" ]; then', workflow)
        for checkpoint in WRONG_SHA_CHECKPOINTS:
            with self.subTest(checkpoint=checkpoint):
                self.assertIn(
                    f"fail-closed-wrong-sha --checkpoint {checkpoint} --pr-state",
                    workflow,
                )
        self.assertIn("protection-fallback escalated after 2 consecutive runs or 24h", workflow)
        self.assertIn("exit 1", workflow)
        validate = (ROOT / ".github" / "workflows" / "cve-catalog-validate.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("CVE_CATALOG_VALIDATION: \"true\"", validate)
        self.assertIn("CVE_CATALOG_VALIDATION_BASE:", validate)
        automation = AUTOMATION.read_text(encoding="utf-8")
        self.assertIn("data-only", automation)
        self.assertIn("enrichment-carryover.json", automation)
        self.assertIn("fail enrichment are dropped", automation)
        self.assertIn("build` check is not", automation)
        self.assertIn("the path gate is the control", automation)
        self.assertIn("catalog-data-path content", automation)
        self.assertIn("content/recipes/cve/*.md", automation)
        self.assertIn(GENERATED_OUTPUT_BRANCH, automation)
        self.assertIn(KAREN_QA_REVIEW_LABEL, automation)
        self.assertIn("fallback label is applied", automation)
        self.assertIn("scopes generator", automation)


if __name__ == "__main__":
    unittest.main()
