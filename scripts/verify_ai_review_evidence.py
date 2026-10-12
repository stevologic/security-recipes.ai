#!/usr/bin/env python3
"""Preview authenticated maintenance review evidence; never grant approval.

No workflow calls this held component. It performs GETs only, uses no model,
and has no activation/merge/status-writing path. Test sources are injected only
through the Python interface; the CLI always uses the fixed GitHub API reader.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import io
import json
import math
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from pathlib import Path
from typing import Any

REPOSITORY = "stevologic/security-recipes.ai"
API = "https://api.github.com/"
ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / ".github/ai-review-verifier.json"
ROLES = ("security", "owning_team", "build", "staging")
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_BYTES = 8 * 1024 * 1024
MAX_RECEIPT = 1024 * 1024
MAX_FILES = 1000
MAX_JSON_DEPTH = 64
API_PATH = re.compile(
    rf"repos/{re.escape(REPOSITORY)}/(?:"
    r"pulls/[1-9][0-9]*(?:/files\?per_page=100&page=[1-9][0-9]*)?|"
    r"git/(?:commits/[0-9a-f]{40}|trees/[0-9a-f]{40}\?recursive=1)|"
    r"actions/(?:runs/[1-9][0-9]*(?:/jobs\?filter=latest&per_page=100|/artifacts\?per_page=100)?|"
    r"artifacts/[1-9][0-9]*/zip))"
)
ASSERTIONS = (
    "authoritative_remediation_changed", "security_policy_changed",
    "workflow_trust_or_permissions_changed", "credentials_or_access_changed",
    "provider_or_budget_changed", "deployment_controls_changed",
    "incident_thresholds_changed",
)


class EvidenceError(ValueError):
    """A fixed diagnostic code; never include response bodies or credentials."""


def integer(value: object) -> bool:
    return type(value) is int and value > 0


def object_json(data: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise EvidenceError("duplicate-json-key")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise EvidenceError("nonfinite-json-value")

    def floating(raw: str) -> float:
        value = float(raw)
        if not math.isfinite(value):
            raise EvidenceError("nonfinite-json-value")
        return value

    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=constant,
                           parse_float=floating)
    except EvidenceError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise EvidenceError("invalid-json") from exc
    if not isinstance(value, dict):
        raise EvidenceError("json-object-required")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise EvidenceError("json-depth-limit")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


class GitHubReader:
    """Fixed-host authenticated metadata; unsigned, bounded artifact redirect."""
    def __init__(self, token: str, opener: Any = None) -> None:
        if not token or any(character.isspace() for character in token):
            raise EvidenceError("invalid-or-missing-github-token")
        self.token = token
        self.opener = opener or urllib.request.build_opener(NoRedirect()).open
        self.requests = 0

    def request(self, path: str) -> urllib.request.Request:
        if not API_PATH.fullmatch(path):
            raise EvidenceError("invalid-api-path")
        self.requests += 1
        if self.requests > 80:
            raise EvidenceError("request-limit")
        return urllib.request.Request(API + path, method="GET", headers={
            "Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def get(self, path: str) -> Any:
        try:
            with self.opener(self.request(path), timeout=30) as response:
                data = response.read(MAX_BYTES + 1)
        except (OSError, ValueError) as exc:
            raise EvidenceError("github-read-failed") from exc
        if len(data) > MAX_BYTES:
            raise EvidenceError("metadata-too-large")
        # Some endpoints are arrays. Duplicate keys/nonfinite values remain rejected.
        if data.lstrip().startswith(b"["):
            wrapped = object_json(b'{"items":' + data + b"}")
            return wrapped["items"]
        return object_json(data)

    def artifact(self, artifact_id: int, expected_digest: str) -> bytes:
        if not integer(artifact_id):
            raise EvidenceError("invalid-artifact-id")
        try:
            with self.opener(self.request(f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"),
                             timeout=30) as response:
                data = response.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if exc.code != 302:
                raise EvidenceError("artifact-read-failed") from exc
            location = exc.headers.get("Location", "")
            try:
                parsed = urllib.parse.urlsplit(location)
                port = parsed.port
            except ValueError as parse_error:
                raise EvidenceError("untrusted-artifact-redirect") from parse_error
            if (parsed.scheme != "https" or parsed.username or parsed.password
                    or port not in (None, 443) or not parsed.hostname
                    or not parsed.hostname.endswith(".blob.core.windows.net")):
                raise EvidenceError("untrusted-artifact-redirect") from exc
            # Never forward the GitHub credential to artifact storage; never follow another redirect.
            try:
                with self.opener(urllib.request.Request(location, method="GET"), timeout=30) as response:
                    data = response.read(MAX_BYTES + 1)
            except (OSError, ValueError) as download_error:
                raise EvidenceError("artifact-download-failed") from download_error
        except (OSError, ValueError) as exc:
            raise EvidenceError("artifact-read-failed") from exc
        if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != expected_digest:
            raise EvidenceError("artifact-size-or-digest-mismatch")
        return data


def policy_check(policy: dict[str, Any]) -> None:
    if set(policy) != {
        "schema_version", "repository", "delegation_active", "blocked_pr_numbers", "allowed_targets",
        "documentation_paths", "asset_patterns", "dependency_paths", "dependabot_actor_id",
        "generated_paths", "trusted_publishers",
    } or policy.get("dependabot_actor_id") != 49699333:
        raise EvidenceError("invalid-policy-schema")
    if (type(policy.get("schema_version")) is not int or policy["schema_version"] != 1
            or policy.get("repository") != REPOSITORY
            or policy.get("delegation_active") is not False):
        raise EvidenceError("inactive-policy-required")
    for key in ("documentation_paths", "asset_patterns", "dependency_paths", "generated_paths"):
        values = policy.get(key)
        if not isinstance(values, list) or any(not safe_path(x) for x in values):
            raise EvidenceError("invalid-policy-paths")
    holds = policy.get("blocked_pr_numbers")
    if not isinstance(holds, list) or any(not integer(x) for x in holds):
        raise EvidenceError("invalid-policy-holds")
    if not {361, 382, 383, 384, 385}.issubset(holds):
        raise EvidenceError("existing-holds-must-remain")
    if policy.get("allowed_targets") != ["development", "main"]:
        raise EvidenceError("invalid-target-policy")
    publishers = policy.get("trusted_publishers")
    if not isinstance(publishers, dict) or set(publishers) != set(ROLES):
        raise EvidenceError("invalid-publisher-registry")
    identities: set[int] = set()
    for role in ROLES:
        entries = publishers[role]
        if not isinstance(entries, list):
            raise EvidenceError("invalid-publisher-registry")
        for entry in entries:
            if (not isinstance(entry, dict) or not integer(entry.get("workflow_id"))
                    or not SHA.fullmatch(str(entry.get("definition_sha", "")))
                    or not re.fullmatch(r"\.github/workflows/[a-zA-Z0-9_-]+\.ya?ml",
                                        str(entry.get("workflow_path", "")))
                    or entry.get("branch") != "main"
                    or not isinstance(entry.get("actor_ids"), list) or not entry["actor_ids"]
                    or any(not integer(x) for x in entry["actor_ids"])
                    or not isinstance(entry.get("job_name"), str) or not entry["job_name"]
                    or not isinstance(entry.get("artifact_name"), str) or not entry["artifact_name"]):
                raise EvidenceError("invalid-publisher-entry")
            if entry["workflow_id"] in identities:
                raise EvidenceError("publisher-workflows-must-be-distinct")
            identities.add(entry["workflow_id"])


def safe_path(value: object) -> bool:
    return (isinstance(value, str) and bool(value) and value.isascii()
            and not value.startswith("/") and "\\" not in value
            and all(part not in ("", ".", "..") for part in value.split("/"))
            and not any(c.isspace() or ord(c) < 32 for c in value))


def tree_files(source: Any, commit_sha: str) -> tuple[str, dict[str, dict[str, str]]]:
    if not SHA.fullmatch(commit_sha):
        raise EvidenceError("invalid-commit-sha")
    commit = source.get(f"repos/{REPOSITORY}/git/commits/{commit_sha}")
    tree_sha = commit.get("tree", {}).get("sha")
    if commit.get("sha") != commit_sha or not SHA.fullmatch(str(tree_sha)):
        raise EvidenceError("invalid-commit-tree")
    tree = source.get(f"repos/{REPOSITORY}/git/trees/{tree_sha}?recursive=1")
    if tree.get("sha") != tree_sha or tree.get("truncated") is not False:
        raise EvidenceError("incomplete-tree")
    entries = tree.get("tree")
    if not isinstance(entries, list):
        raise EvidenceError("missing-tree-inventory")
    files: dict[str, dict[str, str]] = {}
    seen: set[str] = set()
    for entry in entries:
        path = entry.get("path")
        if not safe_path(path) or path in seen:
            raise EvidenceError("unsafe-or-duplicate-tree-path")
        seen.add(path)
        if entry.get("type") == "tree":
            continue
        if entry.get("type") != "blob" or not SHA.fullmatch(str(entry.get("sha", ""))):
            raise EvidenceError("unsupported-tree-entry")
        files[path] = {"sha": entry["sha"], "mode": entry.get("mode", "")}
    return tree_sha, files


def snapshot(source: Any, pr_number: int) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    if not integer(pr_number):
        raise EvidenceError("invalid-pr-number")
    pr = source.get(f"repos/{REPOSITORY}/pulls/{pr_number}")
    head, base = pr.get("head", {}), pr.get("base", {})
    if (pr.get("number") != pr_number or pr.get("state") != "open" or pr.get("merged") is not False
            or head.get("repo", {}).get("full_name") != REPOSITORY
            or base.get("repo", {}).get("full_name") != REPOSITORY
            or not safe_path(head.get("ref")) or not safe_path(base.get("ref"))
            or not SHA.fullmatch(str(head.get("sha", "")))
            or not SHA.fullmatch(str(base.get("sha", "")))):
        raise EvidenceError("invalid-or-cross-repository-pr")
    merge_sha = pr.get("merge_commit_sha")
    if pr.get("mergeable") is not True or not SHA.fullmatch(str(merge_sha)):
        raise EvidenceError("combined-tree-unavailable")
    combined = source.get(f"repos/{REPOSITORY}/git/commits/{merge_sha}")
    parents = combined.get("parents", [])
    if (combined.get("sha") != merge_sha or len(parents) != 2
            or {x.get("sha") for x in parents} != {head["sha"], base["sha"]}
            or not SHA.fullmatch(str(combined.get("tree", {}).get("sha", "")))):
        raise EvidenceError("combined-parent-mismatch")
    files: list[dict[str, Any]] = []
    for page in range(1, MAX_FILES // 100 + 2):
        batch = source.get(f"repos/{REPOSITORY}/pulls/{pr_number}/files?per_page=100&page={page}")
        if not isinstance(batch, list) or len(batch) > 100:
            raise EvidenceError("invalid-file-inventory")
        files.extend(batch)
        if len(files) > MAX_FILES:
            raise EvidenceError("file-inventory-limit")
        if len(batch) < 100:
            break
    if not files or pr.get("changed_files") != len(files):
        raise EvidenceError("incomplete-file-inventory")
    _, head_files = tree_files(source, head["sha"])
    _, base_files = tree_files(source, base["sha"])
    inventory: list[dict[str, Any]] = []
    represented: set[str] = set()
    names: set[str] = set()
    for file in files:
        name, previous = file.get("filename"), file.get("previous_filename")
        if not safe_path(name) or name in names or (previous is not None and not safe_path(previous)):
            raise EvidenceError("unsafe-or-duplicate-changed-path")
        names.add(name)
        represented.add(name)
        if previous is not None:
            represented.add(previous)
        old, new = base_files.get(previous or name), head_files.get(name)
        if ((new is not None and new["sha"] != file.get("sha"))
                or any(x is not None and x["mode"] != "100644" for x in (old, new))):
            raise EvidenceError("changed-blob-or-mode-mismatch")
        inventory.append({"path": name, "previous_path": previous, "status": file.get("status"),
                          "before": old, "after": new})
    changed = {p for p in set(head_files) | set(base_files) if head_files.get(p) != base_files.get(p)}
    if changed != represented:
        raise EvidenceError("file-tree-inventory-mismatch")
    digest = hashlib.sha256(json.dumps(sorted(inventory, key=lambda x: x["path"]),
                                      sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    context = {"repository": REPOSITORY, "pr_number": pr_number, "head_sha": head["sha"],
               "head_repository": head["repo"]["full_name"], "head_ref": head.get("ref"),
               "base_repository": base["repo"]["full_name"], "base_ref": base.get("ref"),
               "base_sha": base["sha"], "combined_sha": merge_sha,
               "combined_tree_sha": combined["tree"]["sha"], "diff_sha256": digest}
    return pr, context, inventory


def scope_kind(pr: dict[str, Any], inventory: list[dict[str, Any]], policy: dict[str, Any]) -> str:
    if pr.get("draft") is not False:
        raise EvidenceError("draft-pr-held")
    if pr["number"] in policy["blocked_pr_numbers"]:
        raise EvidenceError("explicit-pr-hold")
    if pr.get("base", {}).get("ref") not in policy["allowed_targets"]:
        raise EvidenceError("target-not-delegated")
    paths = [p for entry in inventory for p in (entry["path"], entry["previous_path"]) if p is not None]
    forbidden = {"GOVERNANCE.md", "CONTRIBUTING.md", "SECURITY.md", "AGENTS.md", "CODEOWNERS",
                 "docs/cve-enrichment-incident-recovery.md", "docs/shared-maintenance-consumer.md"}
    if any(p in forbidden or p.startswith(("scripts/", "tools/", "actions/", ".agents/", ".codex/"))
           or (p.startswith(".github/") and not p.startswith(".github/readme/")) for p in paths):
        raise EvidenceError("protected-control-path")
    if all(p in policy["documentation_paths"] or any(fnmatch.fnmatchcase(p, pattern)
             and "/" not in p[len(pattern.split("*")[0]):] for pattern in policy["asset_patterns"])
           for p in paths):
        return "documentation-assets"
    if all(p in policy["dependency_paths"] for p in paths):
        author = pr.get("user", {})
        if (author.get("login") != "dependabot[bot]" or author.get("type") != "Bot"
                or author.get("id") != policy["dependabot_actor_id"]):
            raise EvidenceError("unverified-dependency-author")
        return "dependency-patch-minor"
    if paths and all(p in policy["generated_paths"] for p in paths):
        return "owned-generated"
    raise EvidenceError("scope-not-delegated")


def evidence_metadata(source: Any, run_id: int, role: str,
                      policy: dict[str, Any]) -> dict[str, Any]:
    if not integer(run_id):
        raise EvidenceError("invalid-run-id")
    run = source.get(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    entries = [x for x in policy["trusted_publishers"][role] if x["workflow_id"] == run.get("workflow_id")]
    if len(entries) != 1:
        raise EvidenceError("publisher-not-registered")
    publisher = entries[0]
    if (run.get("id") != run_id or run.get("repository", {}).get("full_name") != REPOSITORY
            or run.get("head_repository", {}).get("full_name") != REPOSITORY
            or run.get("path") != publisher["workflow_path"]
            or run.get("head_branch") != publisher["branch"]
            or run.get("head_sha") != publisher["definition_sha"]
            or run.get("actor", {}).get("id") not in publisher["actor_ids"]
            or run.get("triggering_actor", {}).get("id") not in publisher["actor_ids"]
            or run.get("event") != "workflow_dispatch" or run.get("status") != "completed"
            or run.get("conclusion") != "success" or not integer(run.get("run_attempt"))):
        raise EvidenceError("untrusted-or-incomplete-run")
    jobs = source.get(f"repos/{REPOSITORY}/actions/runs/{run_id}/jobs?filter=latest&per_page=100")
    expected = [x for x in jobs.get("jobs", []) if x.get("name") == publisher["job_name"]]
    if (jobs.get("total_count", 101) > 100 or len(expected) != 1
            or expected[0].get("status") != "completed" or expected[0].get("conclusion") != "success"):
        raise EvidenceError("required-job-not-successful")
    artifacts = source.get(f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100")
    matches = [x for x in artifacts.get("artifacts", []) if x.get("name") == publisher["artifact_name"]]
    if artifacts.get("total_count", 101) > 100 or len(matches) != 1:
        raise EvidenceError("ambiguous-or-missing-artifact")
    artifact = matches[0]
    digest = artifact.get("digest", "")
    provenance = artifact.get("workflow_run", {})
    if (artifact.get("expired") is not False or not integer(artifact.get("id"))
            or provenance.get("id") != run_id
            or provenance.get("head_sha") != publisher["definition_sha"]
            or not digest.startswith("sha256:") or not DIGEST.fullmatch(digest[7:])):
        raise EvidenceError("invalid-artifact-provenance")
    return {"run": run, "job": expected[0], "artifact": artifact}


def receipt(source: Any, run_id: int, role: str,
            policy: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    metadata = evidence_metadata(source, run_id, role, policy)
    run, artifact = metadata["run"], metadata["artifact"]
    digest = artifact["digest"]
    archive_bytes = source.artifact(artifact["id"], digest[7:])
    if len(archive_bytes) > MAX_BYTES or hashlib.sha256(archive_bytes).hexdigest() != digest[7:]:
        raise EvidenceError("artifact-size-or-digest-mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            files = archive.infolist()
            if (len(files) != 1 or files[0].filename != "receipt.json"
                    or files[0].file_size > MAX_RECEIPT or files[0].flag_bits & 1
                    or stat.S_ISLNK(files[0].external_attr >> 16)):
                raise EvidenceError("unsafe-receipt-archive")
            if files[0].compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise EvidenceError("unsupported-receipt-compression")
            with archive.open(files[0]) as stream:
                data = stream.read(MAX_RECEIPT + 1)
    except EvidenceError:
        raise
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, zlib.error) as exc:
        raise EvidenceError("invalid-receipt-archive") from exc
    if len(data) > MAX_RECEIPT:
        raise EvidenceError("receipt-too-large")
    result = object_json(data)
    if (type(result.get("schema_version")) is not int or result["schema_version"] != 1
            or result.get("role") != role or not integer(result.get("run_id"))
            or result["run_id"] != run_id or not integer(result.get("run_attempt"))
            or result["run_attempt"] != run["run_attempt"]):
        raise EvidenceError("receipt-run-or-role-mismatch")
    return result, metadata


def verify(source: Any, policy: dict[str, Any], pr_number: int,
           run_ids: dict[str, int]) -> dict[str, Any]:
    result: dict[str, Any] = {"schema_version": 1, "mode": "held-preview",
                             "delegation_active": False, "approval_authority": False,
                             "merge_authority": False, "evidence_valid": False, "blockers": []}
    try:
        policy_check(policy)
        if set(run_ids) != set(ROLES) or len(set(run_ids.values())) != len(ROLES):
            raise EvidenceError("distinct-role-runs-required")
        pr, context, inventory = snapshot(source, pr_number)
        kind = scope_kind(pr, inventory, policy)
        result["context"] = context
        result["scope"] = kind
        evidence = {role: receipt(source, run_ids[role], role, policy) for role in ROLES}
        reports = {role: pair[0] for role, pair in evidence.items()}
        sessions: set[str] = set()
        authoring_identity: tuple[object, str] | None = None
        for role, report in reports.items():
            if (json.dumps(report.get("context"), sort_keys=True) != json.dumps(context, sort_keys=True)
                    or report.get("outcome") != "pass"):
                raise EvidenceError("stale-context-or-nonpass-receipt")
            if role in ("security", "owning_team"):
                session = report.get("reviewer_session_id")
                authoring_session = report.get("authoring_session_id")
                authoring_run = report.get("authoring_run_id")
                if (not isinstance(session, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", session)
                        or session in sessions or report.get("session_origin") != "fresh-independent"
                        or not isinstance(authoring_session, str)
                        or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", authoring_session)
                        or session == authoring_session or "authoring_run_id" not in report
                        or (authoring_run is not None and not integer(authoring_run))
                        or authoring_run in run_ids.values()
                        or report.get("scope") != kind or report.get("unresolved_findings") != []
                        or report.get("scope_assertions") != {key: False for key in ASSERTIONS}):
                    raise EvidenceError("nonindependent-or-blocking-review")
                sessions.add(session)
                identity = (authoring_run, authoring_session)
                if authoring_identity is not None and identity != authoring_identity:
                    raise EvidenceError("authoring-provenance-disagreement")
                authoring_identity = identity
                if kind == "dependency-patch-minor" and (
                    report.get("dependency_metadata", {}).get("update_type") not in
                    ("version-update:semver-patch", "version-update:semver-minor")
                    or report.get("dependency_metadata", {}).get("maintainer_changes") is not False
                    or report.get("dependency_metadata", {}).get("verified") is not True
                ):
                    raise EvidenceError("major-or-unverified-dependency")
                if kind == "owned-generated" and report.get("generated_validation") != {
                    "source": "pass", "ownership": "pass", "factual_policy_unchanged": True,
                }:
                    raise EvidenceError("generated-evidence-not-qualified")
            elif role == "build" and report.get("checks") != {
                key: "pass" for key in ("lint", "python", "node", "catalog", "caddy", "site",
                                         "performance", "compose", "traffic", "images")
            }:
                raise EvidenceError("incomplete-build-evidence")
            elif role == "staging" and (report.get("environment") != "development"
                    or report.get("revision") != context["combined_sha"]):
                raise EvidenceError("staging-revision-mismatch")
        fresh_pr, fresh_context, fresh_inventory = snapshot(source, pr_number)
        if fresh_context != context or fresh_inventory != inventory or scope_kind(fresh_pr, fresh_inventory, policy) != kind:
            raise EvidenceError("pr-changed-during-verification")
        for role in ROLES:
            if evidence_metadata(source, run_ids[role], role, policy) != evidence[role][1]:
                raise EvidenceError("evidence-changed-during-verification")
        result["evidence_valid"] = True
        result["blockers"] = ["delegation-inactive-no-approval-authority"]
    except (EvidenceError, KeyError, TypeError, AttributeError) as exc:
        result["blockers"] = [str(exc) if isinstance(exc, EvidenceError) else "malformed-evidence"]
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true", help="Validate the inactive shipped policy; no API call.")
    parser.add_argument("--pr", type=int)
    for role in ROLES:
        parser.add_argument("--" + role.replace("_", "-") + "-run", type=int)
    args = parser.parse_args(argv)
    try:
        policy = object_json(POLICY.read_bytes())
        policy_check(policy)
        if args.self_check:
            report = {"mode": "held-preview", "delegation_active": False,
                      "approval_authority": False, "merge_authority": False,
                      "policy_valid": True, "blockers": ["delegation-inactive-no-approval-authority"]}
        else:
            runs = {role: getattr(args, role + "_run") for role in ROLES}
            report = verify(GitHubReader(os.environ.get("GITHUB_TOKEN", "")), policy, args.pr, runs)
        print(json.dumps(report, sort_keys=True))
        # Never a successful approval-check exit. Even valid evidence remains held.
        return 3 if report.get("evidence_valid") or report.get("policy_valid") else 1
    except (OSError, EvidenceError) as exc:
        print(json.dumps({"mode": "held-preview", "approval_authority": False,
                          "merge_authority": False, "blockers": [str(exc) if isinstance(exc, EvidenceError)
                                                                   else "policy-read-failed"]}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
