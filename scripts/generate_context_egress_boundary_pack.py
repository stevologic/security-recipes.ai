#!/usr/bin/env python3
"""Generate the SecurityRecipes context egress boundary pack.

The secure context trust pack answers which context may be retrieved.
This pack answers the next enterprise question: where may that context
go after retrieval? It joins the egress boundary model, secure context
registry, and workflow manifest into a deterministic data-boundary
artifact for model providers, MCP servers, telemetry sinks, tenant
gateways, and public corpus destinations.
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
DEFAULT_MODEL = Path("data/assurance/context-egress-boundary-model.json")
DEFAULT_REGISTRY = Path("data/context/secure-context-registry.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_OUTPUT = Path("data/evidence/context-egress-boundary-pack.json")

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")
MACHINE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
VALID_DECISIONS = {
    "allow_public_egress_with_citation",
    "allow_tenant_bound_egress",
    "hold_for_redaction_or_dpa",
    "deny_unapproved_workflow_egress",
    "deny_untrusted_destination",
    "deny_unclassified_egress",
    "kill_session_on_secret_egress",
}
VALID_SENSITIVITY = {
    "public",
    "public_control_evidence",
    "tenant_sensitive",
    "tenant_restricted",
    "regulated",
    "prohibited",
}


class ContextEgressBoundaryError(RuntimeError):
    """Raised when the context egress boundary pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContextEgressBoundaryError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ContextEgressBoundaryError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ContextEgressBoundaryError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContextEgressBoundaryError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContextEgressBoundaryError(f"{label} must be an object")
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


def matches_any(path: Path, repo_root: Path, patterns: list[str]) -> bool:
    rel = normalize_path(path.relative_to(repo_root))
    name = path.name
    return any(fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(rel, pattern) for pattern in patterns)


def source_files(repo_root: Path, source: dict[str, Any], output_path: Path) -> list[Path]:
    # Generated evidence packs expose their own deterministic validators and
    # frequently consume this foundational pack. A narrower scan_root keeps
    # runtime retrieval broad without creating recursive content hashes.
    root = repo_root / str(source.get("scan_root") or source.get("root", ""))
    allowed = [str(pattern) for pattern in source.get("allowed_file_globs", [])]
    excluded = [str(pattern) for pattern in source.get("exclude_file_globs", []) or []]

    if root.is_file():
        candidates = [root]
    elif root.is_dir():
        candidates = [path for path in root.rglob("*") if path.is_file()]
    else:
        return []

    matched: list[Path] = []
    for path in candidates:
        if path.resolve() == output_path.resolve():
            continue
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


def policies_by_id(model: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(policy.get("id")): policy
        for policy in as_list(model.get("data_class_policies"), "data_class_policies")
        if isinstance(policy, dict) and policy.get("id")
    }


def destinations_by_id(model: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(destination.get("id")): destination
        for destination in as_list(model.get("destination_classes"), "destination_classes")
        if isinstance(destination, dict) and destination.get("id")
    }


def validate_model(model: dict[str, Any], registry: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(model.get("schema_version") == PACK_SCHEMA_VERSION, failures, "model schema_version must be 1.0")
    require(len(str(model.get("intent", ""))) >= 80, failures, "model intent must explain the product goal")
    require(registry.get("schema_version") == "1.0", failures, "secure context registry schema_version must be 1.0")
    require(manifest.get("schema_version") == "1.0", failures, "workflow manifest schema_version must be 1.0")

    standards = as_list(model.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 7, failures, "standards_alignment must include at least seven references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        label = f"standards_alignment[{idx}]"
        if not isinstance(standard, dict):
            failures.append(f"{label} must be an object")
            continue
        standard_id = str(standard.get("id", "")).strip()
        require(bool(ID_RE.match(standard_id)), failures, f"{label}.id must be kebab-case")
        require(standard_id not in standard_ids, failures, f"{label}.id duplicates {standard_id}")
        standard_ids.add(standard_id)
        require(str(standard.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(standard.get("coverage", ""))) >= 50, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(model.get("decision_contract"), "decision_contract")
    require(contract.get("default_decision") == "deny_unclassified_egress", failures, "default egress decision must be deny_unclassified_egress")
    decisions = {
        str(decision.get("decision"))
        for decision in as_list(contract.get("decisions"), "decision_contract.decisions")
        if isinstance(decision, dict)
    }
    require(VALID_DECISIONS.issubset(decisions), failures, "decision_contract must define every egress decision")
    require(len(as_list(contract.get("global_rules"), "decision_contract.global_rules")) >= 5, failures, "decision_contract.global_rules must include at least five rules")
    require(len(as_list(contract.get("prohibited_data_classes"), "decision_contract.prohibited_data_classes")) >= 5, failures, "decision_contract.prohibited_data_classes must include secret classes")

    destinations = destinations_by_id(model)
    require(len(destinations) >= 6, failures, "destination_classes must include at least six classes")
    for destination_id, destination in destinations.items():
        require(bool(MACHINE_ID_RE.match(destination_id)), failures, f"{destination_id}: destination id must be a lower-case machine id")
        require(isinstance(destination.get("trusted"), bool), failures, f"{destination_id}: trusted must be boolean")
        require(isinstance(destination.get("external_processor"), bool), failures, f"{destination_id}: external_processor must be boolean")
        require(bool(as_list(destination.get("required_controls"), f"{destination_id}.required_controls")), failures, f"{destination_id}: required_controls are required")

    policies = policies_by_id(model)
    require(len(policies) >= 10, failures, "data_class_policies must include at least ten classes")
    for policy_id, policy in policies.items():
        require(bool(MACHINE_ID_RE.match(policy_id)), failures, f"{policy_id}: data class id must be a lower-case machine id")
        decision = str(policy.get("default_decision"))
        require(decision in VALID_DECISIONS, failures, f"{policy_id}: default_decision is invalid")
        require(str(policy.get("sensitivity")) in VALID_SENSITIVITY, failures, f"{policy_id}: sensitivity is invalid")
        for key in ["allowed_destination_classes", "hold_destination_classes", "prohibited_destination_classes"]:
            for destination_id in as_list(policy.get(key), f"{policy_id}.{key}"):
                require(str(destination_id) in destinations, failures, f"{policy_id}: unknown {key} destination {destination_id}")
        require(bool(as_list(policy.get("required_controls"), f"{policy_id}.required_controls")), failures, f"{policy_id}: required_controls are required")

    tier_map = as_dict(model.get("source_trust_tier_data_class_map"), "source_trust_tier_data_class_map")
    trust_tiers = {
        str(tier.get("id"))
        for tier in as_list(registry.get("trust_tiers"), "registry.trust_tiers")
        if isinstance(tier, dict) and tier.get("id")
    }
    require(trust_tiers.issubset(set(tier_map)), failures, "source_trust_tier_data_class_map must cover every secure context trust tier")
    for tier_id, data_class in tier_map.items():
        require(str(data_class) in policies, failures, f"{tier_id}: maps to unknown data class {data_class}")

    namespace_rules = as_list(model.get("namespace_data_class_map"), "namespace_data_class_map")
    require(len(namespace_rules) >= 8, failures, "namespace_data_class_map must include workflow namespace patterns")
    for idx, rule in enumerate(namespace_rules):
        label = f"namespace_data_class_map[{idx}]"
        if not isinstance(rule, dict):
            failures.append(f"{label} must be an object")
            continue
        require(str(rule.get("pattern", "")).strip(), failures, f"{label}.pattern is required")
        require(str(rule.get("data_class")) in policies, failures, f"{label}: unknown data class {rule.get('data_class')}")

    workflows = as_list(manifest.get("workflows"), "manifest.workflows")
    require(bool(workflows), failures, "workflow manifest must include workflows")
    for workflow in workflows:
        if not isinstance(workflow, dict):
            continue
        for context in workflow.get("mcp_context", []) or []:
            if not isinstance(context, dict):
                continue
            namespace = str(context.get("namespace", "")).strip()
            require(bool(match_namespace(model, namespace)), failures, f"{workflow.get('id')}: namespace has no egress data class mapping: {namespace}")

    return failures


def match_namespace(model: dict[str, Any], namespace: str) -> str | None:
    for rule in model.get("namespace_data_class_map", []) or []:
        if not isinstance(rule, dict):
            continue
        pattern = str(rule.get("pattern", ""))
        if fnmatch.fnmatchcase(namespace, pattern):
            return str(rule.get("data_class"))
    return None


def source_egress_rows(
    *,
    model: dict[str, Any],
    registry: dict[str, Any],
    repo_root: Path,
    output_path: Path,
) -> list[dict[str, Any]]:
    policies = policies_by_id(model)
    tier_map = as_dict(model.get("source_trust_tier_data_class_map"), "source_trust_tier_data_class_map")
    rows: list[dict[str, Any]] = []
    for source in as_list(registry.get("context_sources"), "context_sources"):
        if not isinstance(source, dict):
            continue
        tier_id = str(source.get("trust_tier"))
        data_class_id = str(tier_map.get(tier_id, ""))
        policy = policies.get(data_class_id, {})
        files = source_files(repo_root, source, output_path)
        rows.append(
            {
                "allowed_destination_classes": policy.get("allowed_destination_classes", []),
                "data_class": data_class_id,
                "default_decision": policy.get("default_decision"),
                "exposure": source.get("exposure"),
                "file_count": len(files),
                "hold_destination_classes": policy.get("hold_destination_classes", []),
                "owner": source.get("owner"),
                "prohibited_destination_classes": policy.get("prohibited_destination_classes", []),
                "redaction_required_before_external": policy.get("redaction_required_before_external"),
                "required_controls": policy.get("required_controls", []),
                "root": source.get("root"),
                "sensitivity": policy.get("sensitivity"),
                "source_hash": hash_source(repo_root, files) if files else None,
                "source_id": source.get("id"),
                "tenant_id_required": policy.get("tenant_id_required"),
                "title": source.get("title"),
                "trust_tier": tier_id,
            }
        )
    return sorted(rows, key=lambda row: str(row.get("source_id")))


def workflow_policy_hash(workflow_id: str, rows: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    digest.update(workflow_id.encode("utf-8"))
    digest.update(b"\0")
    for row in rows:
        digest.update(str(row.get("namespace")).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(row.get("data_class")).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(row.get("default_decision")).encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def workflow_egress_rows(model: dict[str, Any], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    policies = policies_by_id(model)
    rows: list[dict[str, Any]] = []
    for workflow in as_list(manifest.get("workflows"), "manifest.workflows"):
        if not isinstance(workflow, dict):
            continue
        namespace_rows: list[dict[str, Any]] = []
        for context in workflow.get("mcp_context", []) or []:
            if not isinstance(context, dict):
                continue
            namespace = str(context.get("namespace", "")).strip()
            data_class = match_namespace(model, namespace) or "unclassified_context"
            policy = policies.get(data_class, {})
            namespace_rows.append(
                {
                    "access": context.get("access"),
                    "allowed_destination_classes": policy.get("allowed_destination_classes", []),
                    "data_class": data_class,
                    "default_decision": policy.get("default_decision", "deny_unclassified_egress"),
                    "hold_destination_classes": policy.get("hold_destination_classes", []),
                    "human_approval_required": policy.get("human_approval_required"),
                    "namespace": namespace,
                    "prohibited_destination_classes": policy.get("prohibited_destination_classes", []),
                    "purpose": context.get("purpose"),
                    "redaction_required_before_external": policy.get("redaction_required_before_external"),
                    "required_controls": policy.get("required_controls", []),
                    "sensitivity": policy.get("sensitivity"),
                    "tenant_id_required": policy.get("tenant_id_required"),
                }
            )
        namespace_rows.sort(key=lambda row: str(row.get("namespace")))
        rows.append(
            {
                "agent_classes": workflow.get("default_agents", []),
                "egress_policy_hash": workflow_policy_hash(str(workflow.get("id")), namespace_rows),
                "maturity_stage": workflow.get("maturity_stage"),
                "namespace_policies": namespace_rows,
                "public_path": workflow.get("public_path"),
                "status": workflow.get("status"),
                "title": workflow.get("title"),
                "workflow_id": workflow.get("id"),
            }
        )
    return sorted(rows, key=lambda row: str(row.get("workflow_id")))


def build_pack(
    *,
    model: dict[str, Any],
    registry: dict[str, Any],
    manifest: dict[str, Any],
    model_path: Path,
    registry_path: Path,
    manifest_path: Path,
    model_ref: Path,
    registry_ref: Path,
    manifest_ref: Path,
    repo_root: Path,
    output_path: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    source_rows = source_egress_rows(
        model=model,
        registry=registry,
        repo_root=repo_root,
        output_path=output_path,
    )
    workflow_rows = workflow_egress_rows(model, manifest)
    data_class_counts = Counter(str(row.get("data_class")) for row in source_rows)
    decision_counts = Counter(str(row.get("default_decision")) for row in source_rows)
    workflow_data_class_counts = Counter(
        str(policy.get("data_class"))
        for workflow in workflow_rows
        for policy in workflow.get("namespace_policies", [])
    )

    policies = list(policies_by_id(model).values())
    destination_rows = as_list(model.get("destination_classes"), "destination_classes")
    tenant_bound_classes = [
        policy.get("id")
        for policy in policies
        if str(policy.get("sensitivity")) in {"tenant_sensitive", "tenant_restricted", "regulated"}
    ]
    prohibited_classes = [
        policy.get("id")
        for policy in policies
        if str(policy.get("sensitivity")) == "prohibited"
    ]

    return {
        "data_class_policies": policies,
        "destination_classes": destination_rows,
        "egress_boundary_summary": {
            "data_class_counts": dict(sorted(data_class_counts.items())),
            "decision_counts": dict(sorted(decision_counts.items())),
            "destination_class_count": len(destination_rows),
            "failure_count": len(failures),
            "namespace_policy_count": sum(len(workflow.get("namespace_policies", [])) for workflow in workflow_rows),
            "prohibited_data_class_count": len(prohibited_classes),
            "source_count": len(source_rows),
            "tenant_bound_data_class_count": len(tenant_bound_classes),
            "workflow_count": len(workflow_rows),
            "workflow_namespace_data_class_counts": dict(sorted(workflow_data_class_counts.items())),
        },
        "egress_decision_contract": model.get("decision_contract", {}),
        "enterprise_adoption_packet": model.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(model.get("last_reviewed", "")),
        "intent": model.get("intent"),
        "positioning": model.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "A data-class decision is only as accurate as the upstream classifier or namespace mapping.",
                "treatment": "Unknown or unmapped data classes fail closed and hold for review before egress."
            },
            {
                "risk": "Vendor settings for retention and residency can drift outside this repository.",
                "treatment": "Runtime requests must provide DPA, zero-data-retention, and region evidence for external processors."
            },
            {
                "risk": "A permitted destination can still return poisoned tool output.",
                "treatment": "Remote MCP and model-provider egress should be paired with connector trust, context poisoning guard, and gateway policy decisions."
            }
        ],
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": {
            "context_egress_boundary_model": {
                "path": normalize_path(model_ref),
                "sha256": sha256_file(model_path),
            },
            "secure_context_registry": {
                "path": normalize_path(registry_ref),
                "sha256": sha256_file(registry_path),
            },
            "workflow_manifest": {
                "path": normalize_path(manifest_ref),
                "sha256": sha256_file(manifest_path),
            },
        },
        "source_egress_map": source_rows,
        "standards_alignment": model.get("standards_alignment", []),
        "workflow_egress_map": workflow_rows,
    }


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in context egress boundary pack is stale.")
    parser.add_argument(
        "--update-if-stale",
        action="store_true",
        help="With --check, refresh the generated pack instead of failing when only the output is stale.",
    )
    return parser.parse_args()


def should_update_stale_output(args: argparse.Namespace) -> bool:
    return (
        bool(args.update_if_stale)
        or os.environ.get("SECURITY_RECIPES_UPDATE_GENERATED") == "1"
    )


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    model_path = resolve(repo_root, args.model)
    registry_path = resolve(repo_root, args.registry)
    manifest_path = resolve(repo_root, args.manifest)
    output_path = resolve(repo_root, args.output)

    try:
        model = load_json(model_path)
        registry = load_json(registry_path)
        manifest = load_json(manifest_path)
        failures = validate_model(model, registry, manifest)
        pack = build_pack(
            model=model,
            registry=registry,
            manifest=manifest,
            model_path=model_path,
            registry_path=registry_path,
            manifest_path=manifest_path,
            model_ref=args.model,
            registry_ref=args.registry,
            manifest_ref=args.manifest,
            repo_root=repo_root,
            output_path=output_path,
            generated_at=args.generated_at,
            failures=failures,
        )
    except ContextEgressBoundaryError as exc:
        print(f"context egress boundary generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)

    if args.check:
        if failures:
            print("context egress boundary validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            if should_update_stale_output(args):
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(next_text, encoding="utf-8")
                print(f"Generated missing context egress boundary pack: {output_path}")
                return 0
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            if should_update_stale_output(args):
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(next_text, encoding="utf-8")
                print(f"Refreshed stale context egress boundary pack: {output_path}")
                return 0
            print(
                f"{output_path} is stale; run scripts/generate_context_egress_boundary_pack.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated context egress boundary pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated context egress boundary pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated context egress boundary pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
