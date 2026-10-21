from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.karen_qa_or_data_only import (
    BOT_GIT_EMAIL,
    BOT_GIT_NAME,
    BOT_PR_LOGINS,
    CATALOG_DATA_FILES,
    CATALOG_SYNC_COMMIT_PATHS,
    CVE_CATALOG_SYNC_BRANCH,
    CVE_CATALOG_SYNC_WORKFLOW,
    EXEMPT_PATHS,
    FILES_API_CAP,
    GATE_PATHS,
    GITHUB_ACTIONS_APP_ID,
    KAREN_QA_APP_ID,
    REQUIRED_CHECK_NAME,
    catalog_sync_commit_paths,
    catalog_sync_git_email,
    catalog_sync_git_user,
    evaluate_karen_qa_or_data_only,
    is_catalog_data_path,
    is_catalog_sync_bot_author,
    is_exempt_path,
    is_gate_path,
    main,
    paths_from_pr_files,
)


ROOT = Path(__file__).resolve().parents[1]
HEAD_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
OTHER_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
REPO = "stevologic/security-recipes.ai"
KAREN_QA_USER_ID = 424242


def _files(*paths: str, status: str = "modified", previous: str | None = None) -> list[dict[str, str]]:
    entries = []
    for path in paths:
        entry = {"filename": path, "status": status, "patch": "untrusted diff text"}
        if previous is not None:
            entry["previous_filename"] = previous
        entries.append(entry)
    return entries


def _catalog_files() -> list[dict[str, str]]:
    return _files(
        "static/api/cve-catalog/manifest.json",
        "data/cve/ai-enrichments.json",
        "data/evidence/agentic-threat-radar.json",
        "content/recipes/cve/ai-enrichment-cve-2026-12345.md",
    )


def _pipeline_files() -> list[dict[str, str]]:
    return _files(
        ".github/workflows/cve-catalog-sync.yml",
        "scripts/sync_cve_catalog.py",
        "scripts/cve_ai_enrichment.py",
        "tests/test_sync_cve_catalog.py",
    )


def _paths_from_files(files: list[dict[str, str]]) -> list[str]:
    paths: list[str] = []
    for entry in files:
        filename = entry.get("filename")
        if filename:
            paths.append(filename)
        previous = entry.get("previous_filename")
        if previous:
            paths.append(previous)
    return paths


def _tree(*paths: str, mode: str = "100644", truncated: bool = False) -> dict[str, object]:
    return {
        "truncated": truncated,
        "tree": [{"path": path, "mode": mode, "type": "blob"} for path in paths],
    }


def _tree_with_modes(modes: dict[str, str], *, truncated: bool = False) -> dict[str, object]:
    return {
        "truncated": truncated,
        "tree": [{"path": path, "mode": mode, "type": "blob"} for path, mode in modes.items()],
    }


def _bot_commit(sha: str = HEAD_SHA) -> dict[str, object]:
    return {
        "sha": sha,
        "commit": {
            "author": {"name": BOT_GIT_NAME, "email": BOT_GIT_EMAIL},
            "committer": {"name": BOT_GIT_NAME, "email": BOT_GIT_EMAIL},
        },
        "author": {"login": "github-actions[bot]", "type": "Bot"},
        "committer": {"login": "github-actions[bot]", "type": "Bot"},
    }


def _human_commit(sha: str = "cccccccccccccccccccccccccccccccccccccccc") -> dict[str, object]:
    return {
        "sha": sha,
        "commit": {
            "author": {"name": "Mallory", "email": "mallory@example.com"},
            "committer": {"name": "Mallory", "email": "mallory@example.com"},
        },
        "author": {"login": "mallory", "type": "User"},
        "committer": {"login": "mallory", "type": "User"},
    }


def _karen_check(
    *,
    conclusion: str = "success",
    app_id: int = KAREN_QA_APP_ID,
    head_sha: str = HEAD_SHA,
    completed_at: str = "2026-10-21T18:00:00Z",
) -> dict[str, object]:
    return {
        "name": "karen-qa",
        "conclusion": conclusion,
        "head_sha": head_sha,
        "completed_at": completed_at,
        "app": {"id": app_id},
    }


def _decide(**overrides: object):
    files = overrides.get("files", _catalog_files())
    if not isinstance(files, list):
        files = _catalog_files()
    paths = _paths_from_files(files)
    payload = {
        "author_login": "github-actions[bot]",
        "author_type": "Bot",
        "head_branch": CVE_CATALOG_SYNC_BRANCH,
        "base_branch": "main",
        "repository": REPO,
        "head_repository": REPO,
        "head_sha": HEAD_SHA,
        "observed_head_sha": HEAD_SHA,
        "changed_files": len(files),
        "files": files,
        "commits": [_bot_commit()],
        "head_tree": _tree(*paths),
        "base_tree": _tree(*paths),
        "statuses": [],
        "check_runs": [],
    }
    payload.update(overrides)
    if "files" in overrides and "changed_files" not in overrides and isinstance(overrides["files"], list):
        payload["changed_files"] = len(overrides["files"])
    if "files" in overrides and isinstance(overrides["files"], list):
        override_paths = _paths_from_files(overrides["files"])
        if "head_tree" not in overrides:
            payload["head_tree"] = _tree(*override_paths)
        if "base_tree" not in overrides:
            payload["base_tree"] = _tree(*override_paths)
    return evaluate_karen_qa_or_data_only(**payload)


class KarenQaOrDataOnlyDecisionTests(unittest.TestCase):
    def test_data_only_passes(self) -> None:
        decision = _decide()
        self.assertEqual(decision.outcome, "data_only")
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.exempt)
        self.assertTrue(decision.data_only)
        self.assertEqual(decision.status_context, REQUIRED_CHECK_NAME)
        self.assertEqual(decision.check_conclusion, "success")

    def test_pipeline_only_fails(self) -> None:
        decision = _decide(files=_pipeline_files())
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.exempt)
        self.assertIn("cve-catalog-sync.yml", decision.reason)

    def test_pipeline_plus_another_file_fails(self) -> None:
        decision = _decide(
            files=_files(
                "scripts/sync_cve_catalog.py",
                "scripts/cve_ai_enrichment.py",
                "README.md",
            )
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertFalse(decision.allowed)
        self.assertIn("scripts/sync_cve_catalog.py", decision.reason)

    def test_gate_file_change_fails(self) -> None:
        for path in GATE_PATHS:
            with self.subTest(path=path):
                decision = _decide(files=_files(path))
                self.assertEqual(decision.outcome, "need_karen_qa")
                self.assertFalse(decision.exempt)
                self.assertIn(path, decision.reason)

    def test_human_author_fails_even_for_catalog_data(self) -> None:
        for author, author_type in (
            ("stevologic", "User"),
            ("outsider", "User"),
            ("security-recipes-cve-bot", "User"),
        ):
            with self.subTest(author=author):
                decision = _decide(author_login=author, author_type=author_type)
                self.assertEqual(decision.outcome, "need_karen_qa")
                self.assertFalse(decision.exempt)
                self.assertIn("CVE catalog sync bot", decision.reason)

    def test_plain_cve_bot_login_without_bot_suffix_fails(self) -> None:
        self.assertFalse(is_catalog_sync_bot_author("security-recipes-cve-bot", "User"))
        self.assertFalse(is_catalog_sync_bot_author("security-recipes-cve-bot", "Bot"))
        self.assertNotIn("security-recipes-cve-bot", BOT_PR_LOGINS)
        decision = _decide(author_login="security-recipes-cve-bot", author_type="Bot")
        self.assertEqual(decision.outcome, "need_karen_qa")

    def test_cve_app_bot_author_passes(self) -> None:
        decision = _decide(author_login="security-recipes-cve-bot[bot]", author_type="Bot")
        self.assertEqual(decision.outcome, "data_only")

    def test_wrong_branch_fails(self) -> None:
        decision = _decide(head_branch="automation/content-refresh")
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("automation/content-refresh", decision.reason)

    def test_human_commit_on_bot_pr_voids_exemption(self) -> None:
        decision = _decide(commits=[_bot_commit(), _human_commit()])
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("not authored or pushed by the CVE catalog sync bot", decision.reason)
        self.assertIn("cccccccccccccccccccccccccccccccccccccccc", decision.reason)

    def test_empty_commit_list_voids_exemption(self) -> None:
        decision = _decide(commits=[])
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("commit list is empty", decision.reason)

    def test_mixed_change_fails(self) -> None:
        decision = _decide(
            files=_files(
                "static/api/cve-catalog/index.json",
                "README.md",
            )
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("README.md", decision.reason)

    def test_rename_out_of_the_allowlist_fails(self) -> None:
        decision = _decide(
            files=_files(
                "README.md",
                status="renamed",
                previous="static/api/cve-catalog/manifest.json",
            )
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("README.md", decision.reason)

    def test_rename_into_the_allowlist_from_outside_fails(self) -> None:
        decision = _decide(
            files=_files(
                "static/api/cve-catalog/manifest.json",
                status="renamed",
                previous="scripts/run_checks.py",
            )
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("scripts/run_checks.py", decision.reason)

    def test_deletion_outside_the_allowlist_fails(self) -> None:
        decision = _decide(files=_files(".github/workflows/build.yml", status="removed"))
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn(".github/workflows/build.yml", decision.reason)

    def test_fork_pr_fails(self) -> None:
        decision = _decide(head_repository="attacker/security-recipes.ai")
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("same repository", decision.reason)

    def test_rename_within_allowlist_passes(self) -> None:
        decision = _decide(
            files=_files(
                "static/api/cve-catalog/shards/moved.json",
                status="renamed",
                previous="static/api/cve-catalog/shards/old.json",
            )
        )
        self.assertEqual(decision.outcome, "data_only")

    def test_deletion_inside_allowlist_passes(self) -> None:
        decision = _decide(files=_files("static/api/cve-catalog/retired.json", status="removed"))
        self.assertEqual(decision.outcome, "data_only")

    def test_policy_and_ownership_and_pipeline_are_not_exempt(self) -> None:
        self.assertTrue(is_catalog_data_path("static/api/cve-catalog/manifest.json"))
        self.assertTrue(is_catalog_data_path("static/api/cve-catalog/shards/a.json.gz"))
        self.assertTrue(is_catalog_data_path("content/recipes/cve/ai-enrichment-cve-2026-1.md"))
        self.assertTrue(is_catalog_data_path("data/evidence/agentic-threat-radar.json"))
        self.assertFalse(is_catalog_data_path("data/policy/mcp-gateway-policy.json"))
        self.assertFalse(is_catalog_data_path("scripts/generated-output-ownership.json"))
        self.assertFalse(is_catalog_data_path("data/context/secure-context-release-pack.json"))
        self.assertFalse(is_catalog_data_path("content/recipes/cve/cve.11tydata.js"))
        self.assertFalse(is_catalog_data_path("content/recipes/cve/_index.html"))
        self.assertFalse(is_catalog_data_path("static/api/cve-catalog/note.txt"))
        self.assertFalse(is_exempt_path("scripts/sync_cve_catalog.py"))
        self.assertFalse(is_exempt_path("scripts/run_checks.py"))
        self.assertTrue(is_gate_path("scripts/karen_qa_or_data_only.py"))
        self.assertFalse(is_exempt_path("scripts/karen_qa_or_data_only.py"))

    def test_backslash_path_is_not_normalized_into_the_allowlist(self) -> None:
        path = r"static\api\cve-catalog\x.json"
        self.assertFalse(is_catalog_data_path(path))
        decision = _decide(files=_files(path))
        self.assertEqual(decision.outcome, "need_karen_qa")

    def test_mcp_gateway_policy_and_ownership_fail(self) -> None:
        for path in (
            "data/policy/mcp-gateway-policy.json",
            "scripts/generated-output-ownership.json",
        ):
            with self.subTest(path=path):
                decision = _decide(files=_files(path))
                self.assertEqual(decision.outcome, "need_karen_qa")
                self.assertIn(path, decision.reason)

    def test_recipe_code_and_html_fail(self) -> None:
        for path in (
            "content/recipes/cve/cve.11tydata.js",
            "content/recipes/cve/_index.html",
        ):
            with self.subTest(path=path):
                decision = _decide(files=_files(path))
                self.assertEqual(decision.outcome, "need_karen_qa")
                self.assertIn(path, decision.reason)


class KarenQaPinAndNewestResultTests(unittest.TestCase):
    def test_unpinned_karen_qa_status_from_anyone_does_not_count(self) -> None:
        decision = _decide(
            files=_files("README.md"),
            statuses=[
                {
                    "context": "karen-qa",
                    "state": "success",
                    "sha": HEAD_SHA,
                    "creator": {"login": "mallory", "id": 1, "type": "User"},
                    "updated_at": "2026-10-21T20:00:00Z",
                }
            ],
        )
        self.assertEqual(decision.outcome, "need_karen_qa")

    def test_github_actions_check_named_karen_qa_does_not_count(self) -> None:
        decision = _decide(
            files=_files("README.md"),
            check_runs=[_karen_check(app_id=GITHUB_ACTIONS_APP_ID)],
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn(str(KAREN_QA_APP_ID), decision.reason)

    def test_karen_qa_app_success_on_exact_head_passes(self) -> None:
        decision = _decide(
            files=_files("README.md"),
            check_runs=[_karen_check()],
        )
        self.assertEqual(decision.outcome, "karen_qa")
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.exempt)

    def test_karen_qa_user_id_status_can_pass_when_pinned(self) -> None:
        decision = _decide(
            files=_files("README.md"),
            statuses=[
                {
                    "context": "karen-qa",
                    "state": "success",
                    "sha": HEAD_SHA,
                    "creator": {"id": KAREN_QA_USER_ID, "login": "karen-qa[bot]", "type": "Bot"},
                    "updated_at": "2026-10-21T20:00:00Z",
                }
            ],
            karen_qa_user_ids=frozenset({KAREN_QA_USER_ID}),
        )
        self.assertEqual(decision.outcome, "karen_qa")

    def test_karen_qa_on_a_different_sha_does_not_count(self) -> None:
        decision = _decide(
            files=_files("README.md"),
            check_runs=[_karen_check(head_sha=OTHER_SHA)],
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn(HEAD_SHA, decision.reason)

    def test_newest_karen_qa_failure_blocks_older_success(self) -> None:
        decision = _decide(
            files=_files("README.md"),
            check_runs=[
                _karen_check(conclusion="success", completed_at="2026-10-21T18:00:00Z"),
                _karen_check(conclusion="failure", completed_at="2026-10-21T19:00:00Z"),
            ],
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertFalse(decision.allowed)

    def test_newest_karen_qa_success_after_older_failure_passes(self) -> None:
        decision = _decide(
            files=_files("README.md"),
            check_runs=[
                _karen_check(conclusion="failure", completed_at="2026-10-21T18:00:00Z"),
                _karen_check(conclusion="success", completed_at="2026-10-21T19:00:00Z"),
            ],
        )
        self.assertEqual(decision.outcome, "karen_qa")

    def test_revoked_later_failure_wins_regardless_of_list_order(self) -> None:
        decision = _decide(
            files=_files("README.md"),
            check_runs=[
                _karen_check(conclusion="failure", completed_at="2026-10-21T21:00:00Z"),
                _karen_check(conclusion="success", completed_at="2026-10-21T17:00:00Z"),
            ],
        )
        self.assertEqual(decision.outcome, "need_karen_qa")


class FilesApiCapAndToctouTests(unittest.TestCase):
    def test_files_api_cap_fails_closed(self) -> None:
        files = _files(*[f"static/api/cve-catalog/{index}.json" for index in range(FILES_API_CAP)])
        decision = _decide(files=files, changed_files=FILES_API_CAP)
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("3000", decision.reason)
        self.assertFalse(decision.exempt)

    def test_file_list_shorter_than_changed_files_fails_closed(self) -> None:
        files = _catalog_files()
        decision = _decide(files=files, changed_files=len(files) + 1)
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("changed_files", decision.reason)
        self.assertFalse(decision.exempt)

    def test_invisible_file_beyond_returned_list_fails_closed(self) -> None:
        files = _files(*[f"static/api/cve-catalog/{index}.json" for index in range(FILES_API_CAP)])
        decision = _decide(files=files, changed_files=FILES_API_CAP + 1)
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertFalse(decision.allowed)

    def test_head_sha_change_during_file_read_fails_closed(self) -> None:
        decision = _decide(observed_head_sha=OTHER_SHA)
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("head SHA changed while reading the file list", decision.reason)

    def test_matching_head_sha_after_file_read_can_pass(self) -> None:
        decision = _decide(observed_head_sha=HEAD_SHA)
        self.assertEqual(decision.outcome, "data_only")


class TreeModeTests(unittest.TestCase):
    def test_symlink_at_head_fails(self) -> None:
        path = "static/api/cve-catalog/manifest.json"
        decision = _decide(
            files=_files(path),
            head_tree=_tree(path, mode="120000"),
            base_tree=_tree(path),
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("120000", decision.reason)

    def test_executable_mode_fails(self) -> None:
        path = "static/api/cve-catalog/manifest.json"
        decision = _decide(
            files=_files(path),
            head_tree=_tree(path, mode="100755"),
            base_tree=_tree(path),
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("100755", decision.reason)

    def test_mode_change_fails(self) -> None:
        path = "static/api/cve-catalog/manifest.json"
        decision = _decide(
            files=_files(path),
            head_tree=_tree(path, mode="100755"),
            base_tree=_tree(path, mode="100644"),
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertRegex(decision.reason, r"100755|mode change")

    def test_truncated_tree_fails_closed(self) -> None:
        path = "static/api/cve-catalog/manifest.json"
        decision = _decide(
            files=_files(path),
            head_tree=_tree(path, truncated=True),
            base_tree=_tree(path),
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("truncated", decision.reason)

    def test_missing_tree_entry_fails_closed(self) -> None:
        decision = _decide(
            files=_files("static/api/cve-catalog/manifest.json"),
            head_tree=_tree(),
            base_tree=_tree(),
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("missing from the git trees", decision.reason)

    def test_regular_file_modes_pass(self) -> None:
        paths = _paths_from_files(_catalog_files())
        decision = _decide(
            head_tree=_tree_with_modes({path: "100644" for path in paths}),
            base_tree=_tree_with_modes({path: "100644" for path in paths}),
        )
        self.assertEqual(decision.outcome, "data_only")


class AllowlistAndCliTests(unittest.TestCase):
    def test_paths_ignore_diff_text(self) -> None:
        files = [
            {
                "filename": "static/api/cve-catalog/manifest.json",
                "status": "modified",
                "patch": "diff --git a/scripts/evil.py b/scripts/evil.py",
            }
        ]
        self.assertEqual(
            paths_from_pr_files(files),
            ("static/api/cve-catalog/manifest.json",),
        )

    def test_allowlist_is_catalog_data_only(self) -> None:
        workflow = (ROOT / CVE_CATALOG_SYNC_WORKFLOW).read_text(encoding="utf-8")
        self.assertEqual(catalog_sync_commit_paths(workflow), CATALOG_SYNC_COMMIT_PATHS)
        self.assertEqual(catalog_sync_git_user(workflow), BOT_GIT_NAME)
        self.assertEqual(catalog_sync_git_email(workflow), BOT_GIT_EMAIL)
        self.assertIn("data/policy/mcp-gateway-policy.json", CATALOG_SYNC_COMMIT_PATHS)
        self.assertIn("scripts/generated-output-ownership.json", CATALOG_SYNC_COMMIT_PATHS)
        self.assertNotIn("data/policy/mcp-gateway-policy.json", EXEMPT_PATHS)
        self.assertNotIn("scripts/generated-output-ownership.json", EXEMPT_PATHS)
        self.assertNotIn("data/context/secure-context-release-pack.json", EXEMPT_PATHS)
        self.assertNotIn(".github/workflows/cve-catalog-sync.yml", EXEMPT_PATHS)
        self.assertNotIn("scripts/sync_cve_catalog.py", EXEMPT_PATHS)
        for path in EXEMPT_PATHS:
            self.assertNotIn("*", path)
            self.assertNotIn("?", path)
        for path in GATE_PATHS:
            self.assertNotIn(path, EXEMPT_PATHS)
        self.assertEqual(
            CATALOG_DATA_FILES,
            (
                "data/cve/ai-enrichments.json",
                "data/cve/ai-generated-recipes.json",
            ),
        )
        self.assertEqual(KAREN_QA_APP_ID, 5400051)
        self.assertEqual(GITHUB_ACTIONS_APP_ID, 15368)

    def test_cli_writes_github_output_and_exits_nonzero_when_karen_qa_is_required(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            files_path = tmp_path / "files.json"
            output_path = tmp_path / "github-output"
            files_path.write_text(json.dumps(_files("README.md")), encoding="utf-8")
            status = main(
                [
                    "--author-login",
                    "stevologic",
                    "--author-type",
                    "User",
                    "--head-branch",
                    CVE_CATALOG_SYNC_BRANCH,
                    "--base-branch",
                    "main",
                    "--repository",
                    REPO,
                    "--head-repository",
                    REPO,
                    "--head-sha",
                    HEAD_SHA,
                    "--changed-files",
                    "1",
                    "--files-json",
                    str(files_path),
                    "--github-output",
                    str(output_path),
                ]
            )
            self.assertEqual(status, 1)
            output = output_path.read_text(encoding="utf-8")
            self.assertIn("outcome=need_karen_qa", output)
            self.assertIn("state=failure", output)
            self.assertIn("conclusion=failure", output)
            self.assertIn("exempt=false", output)
            self.assertIn(f"context={REQUIRED_CHECK_NAME}", output)


if __name__ == "__main__":
    unittest.main()
