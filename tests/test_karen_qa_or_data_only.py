from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.karen_qa_or_data_only import (
    CATALOG_SYNC_COMMIT_PATHS,
    CVE_CATALOG_SYNC_BOT_LOGINS,
    CVE_CATALOG_SYNC_BRANCH,
    CVE_CATALOG_SYNC_WORKFLOW,
    REQUIRED_CHECK_NAME,
    catalog_sync_branch,
    catalog_sync_commit_paths,
    catalog_sync_git_user,
    evaluate_karen_qa_or_data_only,
    is_data_only_catalog_path,
    main,
    paths_from_pr_files,
)


ROOT = Path(__file__).resolve().parents[1]
HEAD_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
OTHER_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
REPO = "stevologic/security-recipes.ai"


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
        "scripts/generated-output-ownership.json",
    )


def _decide(**overrides: object):
    payload = {
        "author_login": "github-actions[bot]",
        "head_branch": CVE_CATALOG_SYNC_BRANCH,
        "base_branch": "main",
        "repository": REPO,
        "head_repository": REPO,
        "head_sha": HEAD_SHA,
        "files": _catalog_files(),
        "statuses": [],
        "check_runs": [],
    }
    payload.update(overrides)
    return evaluate_karen_qa_or_data_only(**payload)


class KarenQaOrDataOnlyDecisionTests(unittest.TestCase):
    def test_bot_plus_data_only_passes(self) -> None:
        decision = _decide()
        self.assertEqual(decision.outcome, "data_only")
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.data_only)
        self.assertEqual(decision.status_state, "success")
        self.assertEqual(decision.status_context, REQUIRED_CHECK_NAME)

    def test_bot_plus_a_workflow_file_fails(self) -> None:
        decision = _decide(
            files=_files(
                "static/api/cve-catalog/manifest.json",
                ".github/workflows/cve-catalog-sync.yml",
            )
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.data_only)
        self.assertIn(".github/workflows/cve-catalog-sync.yml", decision.reason)

    def test_bot_plus_a_script_fails(self) -> None:
        decision = _decide(
            files=_files(
                "static/api/cve-catalog/manifest.json",
                "scripts/sync_cve_catalog.py",
            )
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertFalse(decision.data_only)
        self.assertIn("scripts/sync_cve_catalog.py", decision.reason)

    def test_human_with_data_only_fails(self) -> None:
        decision = _decide(author_login="stevologic")
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertFalse(decision.data_only)
        self.assertIn("stevologic", decision.reason)
        self.assertIn("not the CVE catalog sync bot", decision.reason)

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
                previous="scripts/sync_cve_catalog.py",
            )
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("scripts/sync_cve_catalog.py", decision.reason)

    def test_deletion_outside_the_allowlist_fails(self) -> None:
        decision = _decide(
            files=_files(".github/workflows/build.yml", status="removed")
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn(".github/workflows/build.yml", decision.reason)

    def test_wrong_branch_fails(self) -> None:
        decision = _decide(head_branch="automation/content-refresh")
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn("automation/content-refresh", decision.reason)

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
        decision = _decide(
            files=_files("static/api/cve-catalog/retired.json", status="removed")
        )
        self.assertEqual(decision.outcome, "data_only")

    def test_generated_ownership_file_is_data_not_a_script(self) -> None:
        self.assertTrue(is_data_only_catalog_path("scripts/generated-output-ownership.json"))
        self.assertFalse(is_data_only_catalog_path("scripts/karen_qa_or_data_only.py"))

    def test_non_data_pr_passes_when_karen_qa_succeeded_on_exact_head(self) -> None:
        decision = _decide(
            author_login="stevologic",
            files=_files("README.md"),
            check_runs=[
                {
                    "name": "karen-qa",
                    "conclusion": "success",
                    "head_sha": HEAD_SHA,
                }
            ],
        )
        self.assertEqual(decision.outcome, "karen_qa")
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.data_only)

    def test_karen_qa_on_a_different_sha_does_not_count(self) -> None:
        decision = _decide(
            author_login="stevologic",
            files=_files("README.md"),
            statuses=[
                {
                    "context": "karen-qa",
                    "state": "success",
                    "sha": OTHER_SHA,
                }
            ],
        )
        self.assertEqual(decision.outcome, "need_karen_qa")
        self.assertIn(HEAD_SHA, decision.reason)

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

    def test_allowlist_is_derived_from_the_sync_workflow(self) -> None:
        workflow = (ROOT / CVE_CATALOG_SYNC_WORKFLOW).read_text(encoding="utf-8")
        self.assertEqual(catalog_sync_commit_paths(workflow), CATALOG_SYNC_COMMIT_PATHS)
        self.assertEqual(catalog_sync_branch(workflow), CVE_CATALOG_SYNC_BRANCH)
        self.assertIn(catalog_sync_git_user(workflow), CVE_CATALOG_SYNC_BOT_LOGINS)
        self.assertIn("github-actions[bot]", CVE_CATALOG_SYNC_BOT_LOGINS)

    def test_cli_writes_github_output_and_exits_nonzero_when_karen_qa_is_required(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            files_path = tmp_path / "files.json"
            output_path = tmp_path / "github-output"
            files_path.write_text(
                json.dumps(_files("README.md")),
                encoding="utf-8",
            )
            status = main(
                [
                    "--author-login",
                    "github-actions[bot]",
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
            self.assertIn(f"context={REQUIRED_CHECK_NAME}", output)


if __name__ == "__main__":
    unittest.main()
