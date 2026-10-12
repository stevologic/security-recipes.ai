from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import unittest
import urllib.error
import zipfile
from pathlib import Path

from scripts import verify_ai_review_evidence as verifier


class FixtureSource:
    """Offline authenticated-API contract fixture; no real token or network."""
    def __init__(self) -> None:
        self.policy = json.loads(verifier.POLICY.read_text())
        self.pr_number = 1000
        self.ids = dict(zip(verifier.ROLES, (101, 102, 103, 104)))
        self.head, self.base, self.merge = "1" * 40, "2" * 40, "3" * 40
        self.pr = {
            "number": self.pr_number, "state": "open", "merged": False,
            "draft": False, "auto_merge": None, "mergeable": True, "changed_files": 1,
            "merge_commit_sha": self.merge,
            "user": {"login": "fixture-author", "id": 777, "type": "User"},
            "head": {"sha": self.head, "ref": "fixture-topic", "repo": {"full_name": verifier.REPOSITORY}},
            "base": {"sha": self.base, "ref": "development", "repo": {"full_name": verifier.REPOSITORY}},
        }
        self.commits = {
            self.head: {"sha": self.head, "tree": {"sha": "5" * 40}},
            self.base: {"sha": self.base, "tree": {"sha": "6" * 40}},
            self.merge: {"sha": self.merge, "tree": {"sha": "4" * 40},
                         "parents": [{"sha": self.head}, {"sha": self.base}]},
        }
        self.trees = {
            "5" * 40: {"sha": "5" * 40, "truncated": False, "tree": [
                {"path": "README.md", "type": "blob", "mode": "100644", "sha": "8" * 40}]},
            "6" * 40: {"sha": "6" * 40, "truncated": False, "tree": [
                {"path": "README.md", "type": "blob", "mode": "100644", "sha": "7" * 40}]},
        }
        self.files = [{"filename": "README.md", "sha": "8" * 40, "status": "modified"}]
        self.runs: dict[int, dict[str, object]] = {}
        self.jobs: dict[int, dict[str, object]] = {}
        self.artifacts: dict[int, dict[str, object]] = {}
        self.reports: dict[str, dict[str, object]] = {}
        self.archives: dict[int, bytes] = {}
        self.pull_reads = 0
        self.after_first_snapshot = None
        for index, role in enumerate(verifier.ROLES):
            run_id = self.ids[role]
            definition = "abcd"[index] * 40
            publisher = {"workflow_id": index + 10,
                         "definition_sha": definition,
                         "workflow_path": f".github/workflows/fixture-{role}.yml",
                         "branch": "main", "actor_ids": [555], "job_name": "evidence",
                         "artifact_name": f"fixture-{role}"}
            self.policy["trusted_publishers"][role] = [publisher]
            self.runs[run_id] = {
                "id": run_id, "workflow_id": publisher["workflow_id"], "path": publisher["workflow_path"],
                "head_sha": definition, "head_branch": "main", "actor": {"id": 555},
                "triggering_actor": {"id": 555},
                "repository": {"full_name": verifier.REPOSITORY},
                "head_repository": {"full_name": verifier.REPOSITORY},
                "event": "workflow_dispatch", "status": "completed", "conclusion": "success", "run_attempt": 1,
            }
            self.jobs[run_id] = {"total_count": 1, "jobs": [
                {"name": "evidence", "status": "completed", "conclusion": "success"}]}
        _, context, _ = verifier.snapshot(self, self.pr_number)
        for role in verifier.ROLES:
            report = {"schema_version": 1, "role": role, "run_id": self.ids[role], "run_attempt": 1,
                      "context": copy.deepcopy(context), "outcome": "pass"}
            if role in ("security", "owning_team"):
                report.update({"reviewer_session_id": f"fixture-session-{role}",
                               "authoring_session_id": "fixture-authoring-session", "authoring_run_id": None,
                               "session_origin": "fresh-independent", "unresolved_findings": [],
                               "scope": "documentation-assets",
                               "scope_assertions": {key: False for key in verifier.ASSERTIONS}})
            elif role == "build":
                report["checks"] = {key: "pass" for key in (
                    "lint", "python", "node", "catalog", "caddy", "site", "performance", "compose", "traffic", "images")}
            else:
                report.update({"environment": "development", "revision": self.merge})
            self.reports[role] = report
            self.pack(role)
        self.pull_reads = 0

    def pack(self, role: str, *, member: str = "receipt.json", duplicate: bool = False,
             content: bytes | None = None, compression: int = zipfile.ZIP_STORED) -> None:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=compression) as archive:
            archive.writestr(member, content if content is not None else json.dumps(self.reports[role]))
            if duplicate:
                archive.writestr("other.json", "{}")
        run_id = self.ids[role]
        self.archives[run_id] = stream.getvalue()
        self.artifacts[run_id] = {"total_count": 1, "artifacts": [{
            "id": run_id, "name": f"fixture-{role}", "expired": False,
            "digest": "sha256:" + hashlib.sha256(stream.getvalue()).hexdigest(),
            "workflow_run": {"id": run_id, "head_sha": self.runs[run_id]["head_sha"]},
        }]}

    def get(self, path: str) -> object:
        prefix = f"repos/{verifier.REPOSITORY}/"
        assert path.startswith(prefix)
        path = path[len(prefix):]
        if path == f"pulls/{self.pr_number}":
            self.pull_reads += 1
            if self.pull_reads == 2 and self.after_first_snapshot:
                self.after_first_snapshot()
            return copy.deepcopy(self.pr)
        if path.startswith("git/commits/"):
            return copy.deepcopy(self.commits[path.split("/")[-1]])
        if path.startswith("git/trees/"):
            return copy.deepcopy(self.trees[path.split("/")[-1].split("?")[0]])
        if path.startswith(f"pulls/{self.pr_number}/files?"):
            return copy.deepcopy(self.files if path.endswith("page=1") else [])
        if path.startswith("actions/runs/"):
            parts = path.split("/")
            run_id = int(parts[2])
            if len(parts) == 3:
                return copy.deepcopy(self.runs[run_id])
            if parts[3].startswith("jobs?"):
                return copy.deepcopy(self.jobs[run_id])
            if parts[3].startswith("artifacts?"):
                return copy.deepcopy(self.artifacts[run_id])
        raise AssertionError("Unexpected fixture request: " + path)

    def artifact(self, artifact_id: int, _: str) -> bytes:
        return self.archives[artifact_id]

    def verify(self) -> dict[str, object]:
        return verifier.verify(self, self.policy, self.pr_number, self.ids)


class ReviewEvidenceTests(unittest.TestCase):
    def held(self, fixture: FixtureSource) -> dict[str, object]:
        result = fixture.verify()
        self.assertFalse(result["evidence_valid"], result)
        self.assertIs(result["approval_authority"], False)
        self.assertIs(result["merge_authority"], False)
        return result

    def test_authenticated_complete_preview_still_has_no_authority(self) -> None:
        result = FixtureSource().verify()
        self.assertTrue(result["evidence_valid"], result)
        self.assertFalse(result["delegation_active"])
        self.assertFalse(result["approval_authority"])
        self.assertFalse(result["merge_authority"])
        self.assertEqual(result["blockers"], ["delegation-inactive-no-approval-authority"])

    def test_shipped_registry_is_empty_inactive_and_preserves_holds(self) -> None:
        policy = json.loads(verifier.POLICY.read_text())
        verifier.policy_check(policy)
        self.assertEqual(policy["trusted_publishers"], {role: [] for role in verifier.ROLES})
        fixture = FixtureSource()
        fixture.policy = policy
        self.held(fixture)
        policy["delegation_active"] = True
        self.assertRaises(verifier.EvidenceError, verifier.policy_check, policy)

    def test_current_holds_and_drafts_cannot_be_qualified(self) -> None:
        for hold in (361, 382, 383, 384, 385):
            fixture = FixtureSource()
            fixture.pr_number = hold
            fixture.pr["number"] = hold
            self.assertEqual(self.held(fixture)["blockers"], ["explicit-pr-hold"])
        fixture = FixtureSource()
        fixture.pr["draft"] = True
        self.held(fixture)

    def test_old_holds_cannot_be_removed_from_registry(self) -> None:
        fixture = FixtureSource()
        fixture.policy["blocked_pr_numbers"].remove(385)
        self.assertEqual(self.held(fixture)["blockers"], ["existing-holds-must-remain"])

    def test_fork_and_other_repository_metadata_fail(self) -> None:
        for side in ("head", "base"):
            fixture = FixtureSource()
            fixture.pr[side]["repo"]["full_name"] = "fixture/other"
            self.held(fixture)

    def test_unregistered_targets_cannot_qualify(self) -> None:
        fixture = FixtureSource()
        fixture.pr["base"]["ref"] = "release/fixture"
        self.assertEqual(self.held(fixture)["blockers"], ["target-not-delegated"])

    def test_combined_tree_must_have_exact_head_and_base_parents(self) -> None:
        fixture = FixtureSource()
        fixture.commits[fixture.merge]["parents"][0]["sha"] = "9" * 40
        self.held(fixture)

    def test_complete_file_inventory_and_modes_are_verified(self) -> None:
        for mutate in (
            lambda f: f.pr.update(changed_files=2),
            lambda f: f.trees["5" * 40].update(truncated=True),
            lambda f: f.trees["5" * 40]["tree"][0].update(mode="100755"),
            lambda f: f.trees["5" * 40]["tree"][0].update(type="commit"),
            lambda f: f.files[0].update(sha="9" * 40),
        ):
            fixture = FixtureSource()
            mutate(fixture)
            self.held(fixture)

    def test_unsafe_control_paths_and_renames_are_outside_scope(self) -> None:
        for path in ("GOVERNANCE.md", ".github/workflows/build.yml", "scripts/check_cve_catalog_update.py",
                     "docs/cve-enrichment-incident-recovery.md", "../README.md"):
            fixture = FixtureSource()
            fixture.files[0]["filename"] = path
            for tree in fixture.trees.values():
                tree["tree"][0]["path"] = path
            self.held(fixture)

    def test_missing_or_duplicate_publisher_and_job_fail(self) -> None:
        for mutate in (
            lambda f: f.runs[101].update(workflow_id=999),
            lambda f: f.policy["trusted_publishers"]["security"].append(
                copy.deepcopy(f.policy["trusted_publishers"]["security"][0])),
            lambda f: f.jobs[101]["jobs"].append(copy.deepcopy(f.jobs[101]["jobs"][0])),
            lambda f: f.jobs[101]["jobs"][0].update(conclusion="skipped"),
        ):
            fixture = FixtureSource()
            mutate(fixture)
            self.held(fixture)

    def test_wrong_event_actor_branch_definition_and_fork_fail(self) -> None:
        for key, value in (("event", "pull_request"), ("actor", {"id": 666}),
                           ("head_branch", "feature"), ("head_sha", "9" * 40),
                           ("head_repository", {"full_name": "fixture/fork"}),
                           ("conclusion", "failure"), ("status", "in_progress")):
            fixture = FixtureSource()
            fixture.runs[101][key] = value
            self.held(fixture)

    def test_rerun_initiator_must_be_registered_and_attempt_bound(self) -> None:
        for actor in (None, {"id": 666}, {"id": 555}):
            fixture = FixtureSource()
            fixture.runs[101]["run_attempt"] = 2
            if actor is None:
                fixture.runs[101].pop("triggering_actor")
            else:
                fixture.runs[101]["triggering_actor"] = actor
            fixture.reports["security"]["run_attempt"] = 2
            fixture.pack("security")
            result = fixture.verify()
            self.assertIs(result["evidence_valid"], actor == {"id": 555}, result)
            self.assertIs(result["approval_authority"], False)

    def test_latest_attempt_job_and_artifact_races_invalidate_evidence(self) -> None:
        for mutate in (
            lambda f: f.runs[101].update(run_attempt=2, status="completed", conclusion="failure"),
            lambda f: f.runs[101].update(run_attempt=2),
            lambda f: f.runs[101].update(triggering_actor={"id": 666}),
            lambda f: f.jobs[101]["jobs"][0].update(conclusion="skipped"),
            lambda f: f.artifacts[101]["artifacts"].clear(),
            lambda f: f.artifacts[101]["artifacts"][0].update(expired=True),
            lambda f: f.artifacts[101]["artifacts"][0].update(id=999),
            lambda f: f.artifacts[101]["artifacts"][0].update(digest="sha256:" + "0" * 64),
        ):
            with self.subTest(mutate=mutate):
                fixture = FixtureSource()
                fixture.after_first_snapshot = lambda: mutate(fixture)
                self.held(fixture)

    def test_digest_duplicate_expiry_and_wrong_run_artifact_fail(self) -> None:
        for mutate in (
            lambda a: a.update(digest="sha256:" + "0" * 64),
            lambda a: a.update(expired=True),
            lambda a: a["workflow_run"].update(id=999),
            lambda a: a["workflow_run"].update(head_sha="9" * 40),
        ):
            fixture = FixtureSource()
            mutate(fixture.artifacts[101]["artifacts"][0])
            self.held(fixture)
        fixture = FixtureSource()
        fixture.artifacts[101]["artifacts"].append(copy.deepcopy(fixture.artifacts[101]["artifacts"][0]))
        self.held(fixture)

    def test_zip_path_multiple_members_and_duplicate_json_fail(self) -> None:
        for options in ({"member": "../receipt.json"}, {"duplicate": True},
                        {"content": b'{"schema_version":1,"schema_version":1}'},
                        {"content": b'{"schema_version":NaN}'},
                        {"content": b"[]"}):
            fixture = FixtureSource()
            fixture.pack("security", **options)
            self.held(fixture)

    def test_numeric_and_recursive_json_limits_return_structured_holds(self) -> None:
        for content in (b'{"nested":' + b"1" * 5000 + b"}", b'{"nested":1e999}',
                        b'{"nested":' + b"[" * 10000 + b"0" + b"]" * 10000 + b"}",
                        b'{"nested":' + b"[" * 65 + b"0" + b"]" * 65 + b"}"):
            fixture = FixtureSource()
            fixture.pack("security", content=content)
            result = self.held(fixture)
            self.assertIn(result["blockers"][0],
                          ("invalid-json", "nonfinite-json-value", "json-depth-limit"))

    def test_unsupported_zip_compression_returns_structured_hold(self) -> None:
        fixture = FixtureSource()
        archive = bytearray(fixture.archives[101])
        # Patch both stored compression-method fields to an unsupported method.
        archive[8:10] = (99).to_bytes(2, "little")
        central = archive.index(b"PK\x01\x02")
        archive[central + 10:central + 12] = (99).to_bytes(2, "little")
        fixture.archives[101] = bytes(archive)
        fixture.artifacts[101]["artifacts"][0]["digest"] = "sha256:" + hashlib.sha256(archive).hexdigest()
        self.assertEqual(self.held(fixture)["blockers"], ["unsupported-receipt-compression"])

    def test_reviewed_zip_methods_pass_and_corrupt_lzma_is_held_before_decode(self) -> None:
        fixture = FixtureSource()
        fixture.pack("security", compression=zipfile.ZIP_DEFLATED)
        self.assertTrue(fixture.verify()["evidence_valid"])
        for compression in (zipfile.ZIP_LZMA, zipfile.ZIP_DEFLATED):
            fixture = FixtureSource()
            fixture.pack("security", compression=compression)
            archive = bytearray(fixture.archives[101])
            # Corrupt the actual payload, preserving the surrounding ZIP metadata.
            offset = 30 + int.from_bytes(archive[26:28], "little") + int.from_bytes(archive[28:30], "little")
            archive[offset + 2] ^= 0xFF
            fixture.archives[101] = bytes(archive)
            fixture.artifacts[101]["artifacts"][0]["digest"] = "sha256:" + hashlib.sha256(archive).hexdigest()
            expected = "unsupported-receipt-compression" if compression == zipfile.ZIP_LZMA else "invalid-receipt-archive"
            self.assertEqual(self.held(fixture)["blockers"], [expected])

    def test_invalid_utf8_archive_filename_returns_structured_hold(self) -> None:
        fixture = FixtureSource()
        archive = bytearray(fixture.archives[101])
        central = archive.index(b"PK\x01\x02")
        flags = int.from_bytes(archive[central + 8:central + 10], "little") | 0x800
        archive[central + 8:central + 10] = flags.to_bytes(2, "little")
        archive[central + 46] = 0xFF
        fixture.archives[101] = bytes(archive)
        fixture.artifacts[101]["artifacts"][0]["digest"] = "sha256:" + hashlib.sha256(archive).hexdigest()
        self.assertEqual(self.held(fixture)["blockers"], ["invalid-receipt-archive"])

    def test_receipt_role_run_attempt_and_context_are_bound(self) -> None:
        for key, value in (("role", "owning_team"), ("run_id", 102), ("run_attempt", 2),
                           ("outcome", "warn"), ("schema_version", True)):
            fixture = FixtureSource()
            fixture.reports["security"][key] = value
            fixture.pack("security")
            self.held(fixture)
        for field in ("head_sha", "base_sha", "combined_tree_sha", "diff_sha256"):
            fixture = FixtureSource()
            fixture.reports["security"]["context"][field] = "9" * 40
            fixture.pack("security")
            self.held(fixture)

    def test_same_run_session_authoring_and_missing_authorship_fail(self) -> None:
        for key, value in (("reviewer_session_id", "fixture-session-owning_team"),
                           ("reviewer_session_id", "fixture-authoring-session"),
                           ("authoring_run_id", 101), ("session_origin", "authoring"),
                           ("authoring_session_id", "")):
            fixture = FixtureSource()
            fixture.reports["security"][key] = value
            fixture.pack("security")
            self.held(fixture)
        fixture = FixtureSource()
        fixture.reports["security"].pop("authoring_run_id")
        fixture.pack("security")
        self.held(fixture)
        fixture = FixtureSource()
        fixture.ids["owning_team"] = 101
        self.held(fixture)

    def test_unresolved_findings_and_changed_security_semantics_fail(self) -> None:
        for key, value in (("unresolved_findings", ["fixture-blocker"]),
                           ("scope_assertions", {}), ("scope", "dependency-patch-minor")):
            fixture = FixtureSource()
            fixture.reports["security"][key] = value
            fixture.pack("security")
            self.held(fixture)

    def test_skipped_build_or_wrong_staging_revision_fail(self) -> None:
        fixture = FixtureSource()
        fixture.reports["build"]["checks"]["catalog"] = "skipped"
        fixture.pack("build")
        self.held(fixture)
        fixture = FixtureSource()
        fixture.reports["staging"]["revision"] = fixture.head
        fixture.pack("staging")
        self.held(fixture)

    def test_major_dependency_stays_outside_delegation(self) -> None:
        fixture = FixtureSource()
        fixture.pr["user"] = {"login": "dependabot[bot]", "type": "Bot", "id": 49699333}
        fixture.files[0]["filename"] = "requirements-dev.txt"
        for tree in fixture.trees.values():
            tree["tree"][0]["path"] = "requirements-dev.txt"
        _, context, _ = verifier.snapshot(fixture, fixture.pr_number)
        for role in verifier.ROLES:
            fixture.reports[role]["context"] = context
            if role in ("security", "owning_team"):
                fixture.reports[role].update(scope="dependency-patch-minor", dependency_metadata={
                    "verified": True, "maintainer_changes": False, "update_type": "version-update:semver-major"})
            fixture.pack(role)
        self.assertEqual(self.held(fixture)["blockers"], ["major-or-unverified-dependency"])

    def test_verified_minor_and_qualified_generated_previews_remain_inactive(self) -> None:
        for kind, path in (("dependency-patch-minor", "requirements-dev.txt"),
                           ("owned-generated", "data/cve/fixture.json")):
            fixture = FixtureSource()
            fixture.files[0]["filename"] = path
            for tree in fixture.trees.values():
                tree["tree"][0]["path"] = path
            if kind == "dependency-patch-minor":
                fixture.pr["user"] = {"login": "dependabot[bot]", "type": "Bot", "id": 49699333}
            else:
                fixture.policy["generated_paths"] = [path]
            _, context, _ = verifier.snapshot(fixture, fixture.pr_number)
            for role in verifier.ROLES:
                fixture.reports[role]["context"] = context
                if role in ("security", "owning_team"):
                    fixture.reports[role]["scope"] = kind
                    fixture.reports[role]["dependency_metadata"] = {
                        "verified": True, "maintainer_changes": False, "update_type": "version-update:semver-minor"}
                    fixture.reports[role]["generated_validation"] = {
                        "source": "pass", "ownership": "pass", "factual_policy_unchanged": True}
                fixture.pack(role)
            report = fixture.verify()
            self.assertTrue(report["evidence_valid"], report)
            self.assertFalse(report["approval_authority"])

    def test_scope_registry_cannot_enable_protected_policy_paths(self) -> None:
        fixture = FixtureSource()
        path = "GOVERNANCE.md"
        fixture.policy["documentation_paths"].append(path)
        fixture.files[0]["filename"] = path
        for tree in fixture.trees.values():
            tree["tree"][0]["path"] = path
        self.assertEqual(self.held(fixture)["blockers"], ["protected-control-path"])

    def test_head_and_base_races_invalidate_all_receipts(self) -> None:
        for side in ("head", "base"):
            fixture = FixtureSource()
            def change() -> None:
                previous = fixture.pr[side]["sha"]
                fixture.pr[side]["sha"] = "9" * 40
                fixture.commits["9" * 40] = copy.deepcopy(fixture.commits[previous])
                fixture.commits["9" * 40]["sha"] = "9" * 40
                fixture.merge = "f" * 40
                fixture.pr["merge_commit_sha"] = fixture.merge
                fixture.commits[fixture.merge] = {"sha": fixture.merge, "tree": {"sha": "4" * 40},
                    "parents": [{"sha": fixture.pr["head"]["sha"]}, {"sha": fixture.pr["base"]["sha"]}]}
            fixture.after_first_snapshot = change
            self.assertEqual(self.held(fixture)["blockers"], ["pr-changed-during-verification"])

    def test_same_sha_target_or_head_branch_changes_invalidate_receipts(self) -> None:
        for side, value in (("base", "main"), ("head", "other-topic")):
            fixture = FixtureSource()
            fixture.after_first_snapshot = lambda: fixture.pr[side].update(ref=value)
            self.assertEqual(self.held(fixture)["blockers"], ["pr-changed-during-verification"])

    def test_cli_is_inactive_without_token_network_or_success_exit(self) -> None:
        env = {"PATH": os.defpath}
        result = subprocess.run([sys.executable, str(verifier.ROOT / "scripts/verify_ai_review_evidence.py"),
                                 "--self-check"], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 3)
        self.assertFalse(json.loads(result.stdout)["approval_authority"])
        result = subprocess.run([sys.executable, str(verifier.ROOT / "scripts/verify_ai_review_evidence.py"),
                                 "--pr", "1000"], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)


class Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]


class ReaderBoundaryTests(unittest.TestCase):
    def test_fixed_host_get_and_redirect_never_forward_token(self) -> None:
        requests = []
        payload = b"fixture-zip"
        def opener(request: object, **_: object) -> Response:
            requests.append(request)
            if len(requests) == 1:
                raise urllib.error.HTTPError(request.full_url, 302, "redirect", {
                    "Location": "https://fixture.blob.core.windows.net/artifact.zip?fixture=signed"}, None)
            return Response(payload)
        reader = verifier.GitHubReader("fixture-secret", opener)
        result = reader.artifact(1, hashlib.sha256(payload).hexdigest())
        self.assertEqual(result, payload)
        self.assertEqual(requests[0].get_method(), "GET")
        self.assertEqual(requests[0].get_header("Authorization"), "Bearer fixture-secret")
        self.assertIsNone(requests[1].get_header("Authorization"))

    def test_untrusted_redirect_and_embedded_credentials_fail(self) -> None:
        for url in ("http://fixture.blob.core.windows.net/x", "https://github.com/x",
                    "https://user:secret@fixture.blob.core.windows.net/x",
                    "https://fixture.blob.core.windows.net:bad/x"):
            def opener(request: object, **_: object) -> Response:
                raise urllib.error.HTTPError(request.full_url, 302, "redirect", {"Location": url}, None)
            self.assertRaises(verifier.EvidenceError, verifier.GitHubReader("fixture-secret", opener).artifact,
                              1, "0" * 64)

    def test_metadata_errors_and_large_bodies_are_sanitized(self) -> None:
        def failing(_: object, **kwargs: object) -> Response:
            raise OSError("fixture-secret raw server error")
        reader = verifier.GitHubReader("fixture-secret", failing)
        with self.assertRaises(verifier.EvidenceError) as error:
            reader.get(f"repos/{verifier.REPOSITORY}/pulls/1")
        self.assertEqual(str(error.exception), "github-read-failed")
        reader = verifier.GitHubReader("fixture-secret", lambda *args, **kwargs: Response(b"x" * (verifier.MAX_BYTES + 1)))
        self.assertRaises(verifier.EvidenceError, reader.get, f"repos/{verifier.REPOSITORY}/pulls/1")

    def test_arbitrary_url_namespace_and_malformed_token_are_rejected(self) -> None:
        reader = verifier.GitHubReader("fixture-secret")
        for path in ("https://evil.invalid/x", "repos/other/repo/pulls/1", "repos/stevologic/security-recipes.ai/x\n"):
            self.assertRaises(verifier.EvidenceError, reader.request, path)
        for path in ("repos/stevologic/security-recipes.ai/../other/pulls/1",
                     "repos/stevologic/security-recipes.ai/actions/secrets",
                     "repos/stevologic/security-recipes.ai/pulls/1?user_url=fixture",
                     "repos/stevologic/security-recipes.ai/pulls/%31"):
            self.assertRaises(verifier.EvidenceError, reader.request, path)
        self.assertRaises(verifier.EvidenceError, verifier.GitHubReader, "fixture\nsecret")


if __name__ == "__main__":
    unittest.main()
