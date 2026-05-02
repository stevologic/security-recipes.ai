#!/usr/bin/env python3
"""Generate the SecurityRecipes secure context trust pack.

The site is positioned as the secure context layer for agentic AI. That
claim needs evidence: which context roots are approved, who owns them,
which hashes prove current state, how retrieved text is demoted from
instructions to evidence, and which workflow context package an MCP
server may return.

The output is deterministic by default so CI can run with --check and
fail when the checked-in trust pack drifts from source context.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PACK_SCHEMA_VERSION = "1.0"
DEFAULT_REGISTRY = Path("data/context/secure-context-registry.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_OUTPUT = Path("data/evidence/secure-context-trust-pack.json")

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")
VALID_EXPOSURES = {"public", "tenant", "internal", "prohibited"}


class SecureContextTrustPackError(RuntimeError):
    """Raised when the secure context trust pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SecureContextTrustPackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SecureContextTrustPackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SecureContextTrustPackError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SecureContextTrustPackError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SecureContextTrustPackError(f"{label} must be an object")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def tier_by_id(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(tier.get("id")): tier
        for tier in as_list(registry.get("trust_tiers"), "trust_tiers")
        if isinstance(tier, dict) and tier.get("id")
    }


def matches_any(path: Path, repo_root: Path, patterns: list[str]) -> bool:
    rel = normalize_path(path.relative_to(repo_root))
    name = path.name
    return any(fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(rel, pattern) for pattern in patterns)


def source_files(repo_root: Path, source: dict[str, Any]) -> list[Path]:
    root = repo_root / str(source.get("root", ""))
    allowed = [str(pattern) for pattern in source.get("allowed_file_globs", [])]
    excluded = [str(pattern) for pattern in source.get("exclude_file_globs", []) or []]

    if root.is_file():
        candidates = [root]
    elif root.is_dir():
        candidates = [path for path in root.rglob("*") if path.is_file()]
    else:
        return []

    matched = []
    for path in candidates:
        if not matches_any(path, repo_root, allowed):
            continue
        if excluded and matches_any(path, repo_root, excluded):
            continue
        matched.append(path)
    return sorted(matched, key=lambda item: normalize_path(item.relative_to(repo_root)))


def hash_source(repo_root: Path, files: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in files:
        rel = normalize_path(path.relative_to(repo_root))
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_text(encoding="utf-8").encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def validate_registry(registry: dict[str, Any], manifest: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(registry.get("schema_version") == "1.0", failures, "registry schema_version must be 1.0")
    require(len(str(registry.get("intent", ""))) >= 80, failures, "registry intent must explain the product goal")

    standards = as_list(registry.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 6, failures, "standards_alignment must include at least six references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        label = f"standards_alignment[{idx}]"
        if not isinstance(standard, dict):
            failures.append(f"{label} must be an object")
            continue
        standard_id = str(standard.get("id", "")).strip()
        require(bool(standard_id), failures, f"{label}.id is required")
        require(standard_id not in standard_ids, failures, f"{label}.id duplicates {standard_id}")
        standard_ids.add(standard_id)
        require(str(standard.get("url", "")).startswith("https://"), failures, f"{label}.url must be https")

    tiers = tier_by_id(registry)
    required_tiers = {
        "tier_0_public_reference",
        "tier_1_curated_guidance",
        "tier_2_policy_context",
        "tier_3_customer_runtime_context",
        "tier_4_prohibited_context",
    }
    require(required_tiers.issubset(tiers), failures, "trust_tiers must include all secure-context tiers")
    for tier_id, tier in tiers.items():
        require(bool(as_list(tier.get("minimum_controls"), f"{tier_id}: minimum_controls")), failures, f"{tier_id}: minimum_controls are required")

    contract = as_dict(registry.get("source_contract"), "source_contract")
    allowed_kinds = {str(kind) for kind in as_list(contract.get("required_source_kinds"), "source_contract.required_source_kinds")}
    required_risks = {str(risk) for risk in as_list(contract.get("required_risk_families"), "source_contract.required_risk_families")}
    default_source_ids = {str(source_id) for source_id in as_list(contract.get("default_workflow_source_ids"), "source_contract.default_workflow_source_ids")}

    retrieval_contract = as_dict(registry.get("retrieval_decision_contract"), "retrieval_decision_contract")
    require(retrieval_contract.get("default_decision") == "deny_unregistered_context", failures, "default retrieval decision must be deny_unregistered_context")
    require(len(as_list(retrieval_contract.get("global_rules"), "retrieval_decision_contract.global_rules")) >= 4, failures, "retrieval contract must include global rules")
    require(len(as_list(retrieval_contract.get("prohibited_data_classes"), "retrieval_decision_contract.prohibited_data_classes")) >= 5, failures, "retrieval contract must list prohibited data classes")

    sources = as_list(registry.get("context_sources"), "context_sources")
    require(len(sources) >= int(contract.get("minimum_registered_sources", 1)), failures, "too few context sources are registered")
    seen_ids: set[str] = set()
    covered_risks: set[str] = set()
    for idx, source in enumerate(sources):
        label = f"context_sources[{idx}]"
        if not isinstance(source, dict):
            failures.append(f"{label} must be an object")
            continue

        source_id = str(source.get("id", "")).strip()
        tier_id = str(source.get("trust_tier", "")).strip()
        kind = str(source.get("kind", "")).strip()
        controls = {str(control) for control in as_list(source.get("required_controls"), f"{label}.required_controls")}
        risks = {str(risk) for risk in as_list(source.get("risk_families"), f"{label}.risk_families")}
        files = source_files(repo_root, source)

        require(bool(ID_RE.match(source_id)), failures, f"{label}.id must be kebab-case")
        require(source_id not in seen_ids, failures, f"{label}.id duplicates {source_id}")
        seen_ids.add(source_id)
        require(kind in allowed_kinds, failures, f"{source_id}: kind is not registered: {kind}")
        require(tier_id in tiers, failures, f"{source_id}: trust_tier is unknown: {tier_id}")
        require(str(source.get("exposure")) in VALID_EXPOSURES, failures, f"{source_id}: exposure is invalid")
        require((repo_root / str(source.get("root", ""))).exists(), failures, f"{source_id}: root does not exist: {source.get('root')}")
        require(bool(files), failures, f"{source_id}: no source files matched allowed_file_globs")
        require(bool(as_list(source.get("retrieval_modes"), f"{label}.retrieval_modes")), failures, f"{source_id}: retrieval_modes are required")
        require(bool(as_list(source.get("allowed_file_globs"), f"{label}.allowed_file_globs")), failures, f"{source_id}: allowed_file_globs are required")
        require(int(source.get("freshness_sla_days") or 0) > 0, failures, f"{source_id}: freshness_sla_days must be positive")
        require(bool(source.get("citation_required")), failures, f"{source_id}: citation_required must be true")
        require(len(str(source.get("instruction_handling", ""))) >= 50, failures, f"{source_id}: instruction_handling must be specific")

        owner = as_dict(source.get("owner"), f"{label}.owner")
        require(str(owner.get("accountable_team", "")).strip(), failures, f"{source_id}: owner.accountable_team is required")
        require(str(owner.get("evidence_owner", "")).strip(), failures, f"{source_id}: owner.evidence_owner is required")

        minimum_controls = {str(control) for control in tiers.get(tier_id, {}).get("minimum_controls", [])}
        missing_controls = sorted(minimum_controls - controls)
        require(not missing_controls, failures, f"{source_id}: missing trust-tier controls: {missing_controls}")
        unknown_risks = sorted(risks - required_risks)
        require(not unknown_risks, failures, f"{source_id}: unknown risk families: {unknown_risks}")
        covered_risks.update(risks)

    missing_defaults = sorted(default_source_ids - seen_ids)
    require(not missing_defaults, failures, f"default workflow source IDs are not registered: {missing_defaults}")
    missing_risks = sorted(required_risks - covered_risks)
    require(not missing_risks, failures, f"registered sources do not cover risk families: {missing_risks}")

    workflows = as_list(manifest.get("workflows"), "manifest.workflows")
    require(bool(workflows), failures, "workflow manifest must include workflows")
    for idx, workflow in enumerate(workflows):
        label = f"manifest.workflows[{idx}]"
        if not isinstance(workflow, dict):
            failures.append(f"{label} must be an object")
            continue
        workflow_id = str(workflow.get("id", "")).strip()
        require(bool(ID_RE.match(workflow_id)), failures, f"{label}.id must be kebab-case")
        require(bool(workflow.get("mcp_context")), failures, f"{workflow_id}: mcp_context is required for context mapping")

    return failures


def retrieval_decision(source: dict[str, Any]) -> str:
    tier_id = str(source.get("trust_tier"))
    if tier_id == "tier_4_prohibited_context":
        return "kill_session_on_prohibited_context"
    if tier_id == "tier_3_customer_runtime_context":
        return "hold_for_customer_context"
    if tier_id == "tier_2_policy_context":
        return "allow_policy_context_with_citation"
    return "allow_public_context"


def build_source_summaries(registry: dict[str, Any], repo_root: Path) -> list[dict[str, Any]]:
    tiers = tier_by_id(registry)
    rows: list[dict[str, Any]] = []
    for source in as_list(registry.get("context_sources"), "context_sources"):
        if not isinstance(source, dict):
            continue
        root = repo_root / str(source.get("root", ""))
        files = source_files(repo_root, source)
        byte_count = sum(path.stat().st_size for path in files)
        tier_id = str(source.get("trust_tier"))
        rows.append(
            {
                "allowed_file_globs": source.get("allowed_file_globs", []),
                "authority": source.get("authority"),
                "byte_count": byte_count,
                "citation_required": source.get("citation_required"),
                "decision": retrieval_decision(source),
                "exclude_file_globs": source.get("exclude_file_globs", []),
                "exposure": source.get("exposure"),
                "file_count": len(files),
                "freshness_sla_days": source.get("freshness_sla_days"),
                "freshness_state": "declared_current",
                "hash_algorithm": "sha256",
                "instruction_handling": source.get("instruction_handling"),
                "kind": source.get("kind"),
                "owner": source.get("owner"),
                "poisoning_controls": source.get("poisoning_controls", []),
                "registered_files": [
                    normalize_path(path.relative_to(repo_root))
                    for path in files[:25]
                ],
                "registered_files_truncated": len(files) > 25,
                "required_controls": source.get("required_controls", []),
                "retrieval_modes": source.get("retrieval_modes", []),
                "risk_families": source.get("risk_families", []),
                "root": source.get("root"),
                "root_type": "file" if root.is_file() else "directory" if root.is_dir() else "missing",
                "source_hash": hash_source(repo_root, files),
                "source_id": source.get("id"),
                "title": source.get("title"),
                "trust_tier": {
                    "id": tier_id,
                    "title": tiers.get(tier_id, {}).get("title"),
                },
            }
        )
    return sorted(rows, key=lambda row: str(row.get("source_id")))


def context_package_hash(workflow_id: str, sources: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    digest.update(workflow_id.encode("utf-8"))
    digest.update(b"\0")
    for source in sorted(sources, key=lambda row: str(row.get("source_id"))):
        digest.update(str(source.get("source_id")).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(source.get("source_hash")).encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def build_workflow_context_map(
    manifest: dict[str, Any],
    registry: dict[str, Any],
    source_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    source_by_source_id = {str(source.get("source_id")): source for source in source_rows}
    default_source_ids = [
        str(source_id)
        for source_id in registry.get("source_contract", {}).get("default_workflow_source_ids", [])
    ]
    rows: list[dict[str, Any]] = []
    for workflow in as_list(manifest.get("workflows"), "manifest.workflows"):
        if not isinstance(workflow, dict):
            continue
        workflow_id = str(workflow.get("id"))
        package_sources = [
            source_by_source_id[source_id]
            for source_id in default_source_ids
            if source_id in source_by_source_id
        ]
        rows.append(
            {
                "agent_classes": workflow.get("default_agents", []),
                "context_package_hash": context_package_hash(workflow_id, package_sources),
                "context_package_scope": "SecurityRecipes open context only; customer runtime context must be retrieved tenant-side through a governed MCP gateway.",
                "context_source_count": len(package_sources),
                "freshness_state": "declared_current",
                "maturity_stage": workflow.get("maturity_stage"),
                "mcp_namespaces": [
                    context.get("namespace")
                    for context in workflow.get("mcp_context", [])
                    if isinstance(context, dict) and context.get("namespace")
                ],
                "public_path": workflow.get("public_path"),
                "source_ids": default_source_ids,
                "status": workflow.get("status"),
                "title": workflow.get("title"),
                "workflow_id": workflow_id,
            }
        )
    return rows


def build_pack(
    *,
    registry: dict[str, Any],
    manifest: dict[str, Any],
    registry_path: Path,
    manifest_path: Path,
    registry_ref: Path,
    manifest_ref: Path,
    repo_root: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    source_rows = build_source_summaries(registry, repo_root)
    workflow_rows = build_workflow_context_map(manifest, registry, source_rows)
    tier_counts = Counter(str(source.get("trust_tier", {}).get("id")) for source in source_rows)
    kind_counts = Counter(str(source.get("kind")) for source in source_rows)
    decision_counts = Counter(str(source.get("decision")) for source in source_rows)
    risk_counts = Counter(
        str(risk)
        for source in source_rows
        for risk in source.get("risk_families", [])
    )

    return {
        "context_sources": source_rows,
        "context_trust_summary": {
            "context_source_count": len(source_rows),
            "default_decision": registry.get("retrieval_decision_contract", {}).get("default_decision"),
            "decision_counts": dict(sorted(decision_counts.items())),
            "failure_count": len(failures),
            "prohibited_data_class_count": len(registry.get("retrieval_decision_contract", {}).get("prohibited_data_classes", []) or []),
            "registered_byte_count": sum(int(source.get("byte_count") or 0) for source in source_rows),
            "registered_file_count": sum(int(source.get("file_count") or 0) for source in source_rows),
            "risk_family_counts": dict(sorted(risk_counts.items())),
            "source_kind_counts": dict(sorted(kind_counts.items())),
            "sources_requiring_citation": sum(1 for source in source_rows if source.get("citation_required")),
            "trust_tier_counts": dict(sorted(tier_counts.items())),
            "workflow_context_package_count": len(workflow_rows),
        },
        "enterprise_adoption_packet": registry.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(registry.get("last_reviewed", "")),
        "intent": registry.get("intent"),
        "positioning": registry.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "Source-controlled public context does not prove customer runtime data quality.",
                "treatment": "Customer findings, tickets, logs, and repository context must be retrieved tenant-side through the MCP gateway with redaction and audit logging."
            },
            {
                "risk": "Context hashes prove provenance, not semantic correctness.",
                "treatment": "Workflow owners still need review, evals, and scanner evidence before context changes promote to production use."
            },
            {
                "risk": "Tool descriptions and retrieved evidence can carry adversarial instructions.",
                "treatment": "Retrieved text is demoted to evidence, and gateway/system policy remains the authority for actions."
            }
        ],
        "retrieval_decision_contract": registry.get("retrieval_decision_contract", {}),
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": {
            "secure_context_registry": {
                "path": normalize_path(registry_ref),
                "sha256": sha256_file(registry_path),
            },
            "workflow_manifest": {
                "path": normalize_path(manifest_ref),
                "sha256": sha256_file(manifest_path),
            },
        },
        "source_contract": registry.get("source_contract", {}),
        "standards_alignment": registry.get("standards_alignment", []),
        "trust_tiers": registry.get("trust_tiers", []),
        "workflow_context_map": workflow_rows,
    }


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in secure context trust pack is stale.")
    parser.add_argument(
        "--update-if-stale",
        action="store_true",
        help="With --check, refresh the generated trust pack instead of failing when only the output is stale.",
    )
    return parser.parse_args()


def should_update_stale_output(args: argparse.Namespace) -> bool:
    return (
        bool(args.update_if_stale)
        or os.environ.get("SECURITY_RECIPES_UPDATE_GENERATED") == "1"
        or os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
    )


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    registry_path = resolve(repo_root, args.registry)
    manifest_path = resolve(repo_root, args.manifest)
    output_path = resolve(repo_root, args.output)

    try:
        registry = load_json(registry_path)
        manifest = load_json(manifest_path)
        failures = validate_registry(registry, manifest, repo_root)
        pack = build_pack(
            registry=registry,
            manifest=manifest,
            registry_path=registry_path,
            manifest_path=manifest_path,
            registry_ref=args.registry,
            manifest_ref=args.manifest,
            repo_root=repo_root,
            generated_at=args.generated_at,
            failures=failures,
        )
    except SecureContextTrustPackError as exc:
        print(f"secure context trust pack generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)

    if args.check:
        if failures:
            print("secure context trust pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            if should_update_stale_output(args):
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(next_text, encoding="utf-8")
                print(f"Generated missing secure context trust pack: {output_path}")
                return 0
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            if should_update_stale_output(args):
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(next_text, encoding="utf-8")
                print(f"Refreshed stale secure context trust pack: {output_path}")
                return 0
            print(
                f"{output_path} is stale; run scripts/generate_secure_context_trust_pack.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated secure context trust pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated secure context trust pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated secure context trust pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
