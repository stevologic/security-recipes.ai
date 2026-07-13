#!/usr/bin/env python3
"""Generate the SecurityRecipes MCP connector trust pack.

The workflow manifest says which MCP namespaces a remediation workflow
uses. The gateway policy says whether those namespaces are read, scoped
write, ticket write, or approval-gated. The connector trust registry
answers the next enterprise question: is each namespace attached to a
reviewed connector with the right auth, network, audit, result
inspection, promotion, and kill-signal controls?

The output is deterministic by default so CI can run with --check and
fail when the checked-in trust pack drifts from source controls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


TRUST_PACK_SCHEMA_VERSION = "1.0"
DEFAULT_REGISTRY = Path("data/mcp/connector-trust-registry.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_OUTPUT = Path("data/evidence/mcp-connector-trust-pack.json")

VALID_STATUSES = {"experimental", "pilot", "production", "deprecated", "retired"}
VALID_TRANSPORTS = {"stdio", "streamable-http", "http", "sse"}
VALID_ACCESS_MODES = {"read", "write_branch", "write_ticket", "approval_required"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")
NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$")


class TrustPackError(RuntimeError):
    """Raised when the connector trust pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TrustPackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise TrustPackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise TrustPackError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise TrustPackError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TrustPackError(f"{label} must be an object")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def sha256_file(path: Path) -> str:
    # Hash canonical UTF-8 text so evidence hashes are stable across
    # Windows CRLF and GitHub Actions Ubuntu LF checkouts.
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def normalize_path(path: Path) -> str:
    return path.as_posix()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def connector_by_namespace(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    connectors = as_list(registry.get("connectors"), "registry.connectors")
    return {
        str(connector.get("namespace")): connector
        for connector in connectors
        if isinstance(connector, dict) and connector.get("namespace")
    }


def trust_tier_by_id(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tiers = as_list(registry.get("trust_tiers"), "registry.trust_tiers")
    return {
        str(tier.get("id")): tier
        for tier in tiers
        if isinstance(tier, dict) and tier.get("id")
    }


def workflow_context_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for workflow in as_list(manifest.get("workflows"), "manifest.workflows"):
        item = as_dict(workflow, "manifest.workflow")
        workflow_id = str(item.get("id"))
        for context in as_list(item.get("mcp_context"), f"{workflow_id}: mcp_context"):
            context_item = as_dict(context, f"{workflow_id}: mcp_context item")
            rows.append(
                {
                    "access": context_item.get("access"),
                    "namespace": context_item.get("namespace"),
                    "purpose": context_item.get("purpose"),
                    "status": item.get("status"),
                    "title": item.get("title"),
                    "workflow_id": workflow_id,
                }
            )
    return rows


def policy_scope_by_workflow(policy_pack: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    output: dict[str, dict[str, dict[str, Any]]] = {}
    for policy in as_list(policy_pack.get("workflow_policies"), "policy_pack.workflow_policies"):
        item = as_dict(policy, "policy_pack.workflow_policy")
        workflow_id = str(item.get("workflow_id"))
        tool_access = as_dict(item.get("tool_access"), f"{workflow_id}: tool_access")
        output[workflow_id] = {
            str(scope.get("namespace")): scope
            for scope in as_list(tool_access.get("allowed_mcp_scopes"), f"{workflow_id}: allowed_mcp_scopes")
            if isinstance(scope, dict) and scope.get("namespace")
        }
    return output


def validate_registry(registry: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(registry.get("schema_version") == "1.0", failures, "registry schema_version must be 1.0")
    require(len(str(registry.get("intent", ""))) >= 60, failures, "registry intent must explain product goal")

    standards = as_list(registry.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 5, failures, "standards_alignment must include at least five references")
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

    tiers = trust_tier_by_id(registry)
    require(
        {"tier_0_public_context", "tier_1_internal_read", "tier_2_scoped_write", "tier_3_approval_required", "tier_4_prohibited"}.issubset(tiers),
        failures,
        "trust_tiers must include public, internal-read, scoped-write, approval-required, and prohibited tiers",
    )
    for tier_id, tier in tiers.items():
        require(bool(as_list(tier.get("minimum_controls"), f"{tier_id}: minimum_controls")), failures, f"{tier_id}: minimum_controls are required")

    connectors = as_list(registry.get("connectors"), "connectors")
    require(connectors, failures, "connectors must not be empty")
    seen_ids: set[str] = set()
    seen_namespaces: set[str] = set()
    for idx, connector in enumerate(connectors):
        label = f"connectors[{idx}]"
        if not isinstance(connector, dict):
            failures.append(f"{label} must be an object")
            continue

        connector_id = str(connector.get("id", "")).strip()
        namespace = str(connector.get("namespace", "")).strip()
        tier_id = str(connector.get("trust_tier", "")).strip()
        status = str(connector.get("status", "")).strip()
        access_modes = {str(item) for item in as_list(connector.get("access_modes"), f"{label}.access_modes")}
        controls = {str(item) for item in as_list(connector.get("required_controls"), f"{label}.required_controls")}

        require(bool(ID_RE.match(connector_id)), failures, f"{label}.id must be kebab-case")
        require(connector_id not in seen_ids, failures, f"{label}.id duplicates {connector_id}")
        seen_ids.add(connector_id)

        require(bool(NAMESPACE_RE.match(namespace)), failures, f"{label}.namespace must be dotted namespace")
        require("*" not in namespace, failures, f"{label}.namespace must not use wildcards")
        require(namespace not in seen_namespaces, failures, f"{label}.namespace duplicates {namespace}")
        seen_namespaces.add(namespace)

        require(status in VALID_STATUSES, failures, f"{label}.status is invalid")
        require(tier_id in tiers, failures, f"{label}.trust_tier is unknown: {tier_id}")
        require(str(connector.get("transport")) in VALID_TRANSPORTS, failures, f"{label}.transport is invalid")
        require(access_modes.issubset(VALID_ACCESS_MODES), failures, f"{label}.access_modes has invalid values")
        require(bool(access_modes), failures, f"{label}.access_modes must not be empty")

        owner = as_dict(connector.get("owner"), f"{label}.owner")
        require(str(owner.get("accountable_team", "")).strip(), failures, f"{label}.owner.accountable_team is required")
        require(str(owner.get("escalation", "")).strip(), failures, f"{label}.owner.escalation is required")

        minimum_controls = {str(item) for item in tiers.get(tier_id, {}).get("minimum_controls", [])}
        missing_controls = sorted(minimum_controls - controls)
        require(not missing_controls, failures, f"{connector_id}: missing tier controls: {missing_controls}")

        evidence = as_list(connector.get("evidence"), f"{label}.evidence")
        require(len(evidence) >= 3, failures, f"{connector_id}: at least three evidence records are required")
        evidence_ids: set[str] = set()
        for evidence_idx, evidence_item in enumerate(evidence):
            evidence_label = f"{connector_id}: evidence[{evidence_idx}]"
            if not isinstance(evidence_item, dict):
                failures.append(f"{evidence_label} must be an object")
                continue
            evidence_id = str(evidence_item.get("id", "")).strip()
            require(bool(ID_RE.match(evidence_id)), failures, f"{evidence_label}.id must be kebab-case")
            require(evidence_id not in evidence_ids, failures, f"{evidence_label}.id duplicates {evidence_id}")
            evidence_ids.add(evidence_id)
            require(str(evidence_item.get("source", "")).strip(), failures, f"{evidence_label}.source is required")
            require(str(evidence_item.get("retention", "")).strip(), failures, f"{evidence_label}.retention is required")
            require(str(evidence_item.get("evidence_owner", "")).strip(), failures, f"{evidence_label}.evidence_owner is required")

        require(bool(as_list(connector.get("promotion_criteria"), f"{label}.promotion_criteria")), failures, f"{connector_id}: promotion_criteria are required")
        require(bool(as_list(connector.get("kill_signals"), f"{label}.kill_signals")), failures, f"{connector_id}: kill_signals are required")
        require(bool(as_list(connector.get("allowed_operations"), f"{label}.allowed_operations")), failures, f"{connector_id}: allowed_operations are required")
        require(bool(as_list(connector.get("forbidden_operations"), f"{label}.forbidden_operations")), failures, f"{connector_id}: forbidden_operations are required")
        require(bool(as_list(connector.get("data_classes"), f"{label}.data_classes")), failures, f"{connector_id}: data_classes are required")

        write_modes = {"write_branch", "write_ticket", "approval_required"} & access_modes
        if write_modes:
            require(tier_id in {"tier_2_scoped_write", "tier_3_approval_required"}, failures, f"{connector_id}: write modes need tier_2 or tier_3")
            require("write_scope_enforcement" in controls, failures, f"{connector_id}: write modes need write_scope_enforcement")
        if "approval_required" in access_modes:
            require(tier_id == "tier_3_approval_required", failures, f"{connector_id}: approval_required access needs tier_3")
            require({"typed_human_approval", "two_key_review"}.issubset(controls), failures, f"{connector_id}: approval_required access needs typed approval and two-key review")

    return failures


def validate_manifest_policy_alignment(
    *,
    registry: dict[str, Any],
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    manifest_path: Path,
) -> list[str]:
    failures: list[str] = []
    connectors = connector_by_namespace(registry)
    contexts = workflow_context_rows(manifest)

    missing_namespaces = sorted({str(row.get("namespace")) for row in contexts} - set(connectors))
    require(not missing_namespaces, failures, f"workflow namespaces missing from connector registry: {missing_namespaces}")

    for row in contexts:
        namespace = str(row.get("namespace"))
        access = str(row.get("access"))
        workflow_id = str(row.get("workflow_id"))
        connector = connectors.get(namespace)
        if not connector:
            continue
        connector_modes = {str(item) for item in connector.get("access_modes", [])}
        require(access in connector_modes, failures, f"{workflow_id}: namespace {namespace} access {access} is not allowed by connector registry")

    policies = policy_scope_by_workflow(policy_pack)
    policy_source = as_dict(policy_pack.get("source_manifest"), "policy_pack.source_manifest")
    require(
        policy_source.get("sha256") == sha256_file(manifest_path),
        failures,
        "gateway policy source_manifest.sha256 does not match workflow manifest",
    )
    require(set(policies) == {str(workflow.get("id")) for workflow in manifest.get("workflows", []) if isinstance(workflow, dict)}, failures, "gateway policy workflow IDs must match manifest workflow IDs")

    for workflow_id, scopes in policies.items():
        for namespace, scope in scopes.items():
            connector = connectors.get(namespace)
            if not connector:
                continue
            access = str(scope.get("access"))
            require(access in connector.get("access_modes", []), failures, f"{workflow_id}: policy namespace {namespace} access {access} is not allowed by registry")

    return failures


def connector_summary(connector: dict[str, Any], tiers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    tier_id = str(connector.get("trust_tier"))
    return {
        "access_modes": connector.get("access_modes", []),
        "allowed_operations": connector.get("allowed_operations", []),
        "category": connector.get("category"),
        "connector_id": connector.get("id"),
        "data_classes": connector.get("data_classes", []),
        "deployment_model": connector.get("deployment_model"),
        "evidence_records": [
            {
                "evidence_owner": item.get("evidence_owner"),
                "id": item.get("id"),
                "retention": item.get("retention"),
                "source": item.get("source"),
            }
            for item in connector.get("evidence", [])
            if isinstance(item, dict)
        ],
        "forbidden_operations": connector.get("forbidden_operations", []),
        "kill_signals": connector.get("kill_signals", []),
        "namespace": connector.get("namespace"),
        "owner": connector.get("owner"),
        "promotion_criteria": connector.get("promotion_criteria", []),
        "required_controls": connector.get("required_controls", []),
        "status": connector.get("status"),
        "title": connector.get("title"),
        "transport": connector.get("transport"),
        "trust_tier": {
            "id": tier_id,
            "title": tiers.get(tier_id, {}).get("title"),
        },
    }


def build_workflow_connector_map(
    *,
    manifest: dict[str, Any],
    registry: dict[str, Any],
    policy_pack: dict[str, Any],
) -> list[dict[str, Any]]:
    connectors = connector_by_namespace(registry)
    policy_scopes = policy_scope_by_workflow(policy_pack)
    rows = []
    for workflow in as_list(manifest.get("workflows"), "manifest.workflows"):
        item = as_dict(workflow, "manifest.workflow")
        workflow_id = str(item.get("id"))
        mapped_contexts = []
        for context in as_list(item.get("mcp_context"), f"{workflow_id}: mcp_context"):
            context_item = as_dict(context, f"{workflow_id}: mcp_context item")
            namespace = str(context_item.get("namespace"))
            connector = connectors.get(namespace, {})
            policy_scope = policy_scopes.get(workflow_id, {}).get(namespace, {})
            mapped_contexts.append(
                {
                    "access": context_item.get("access"),
                    "connector_id": connector.get("id"),
                    "connector_status": connector.get("status"),
                    "decision": policy_scope.get("decision"),
                    "namespace": namespace,
                    "purpose": context_item.get("purpose"),
                    "trust_tier": connector.get("trust_tier"),
                }
            )
        rows.append(
            {
                "connector_context": mapped_contexts,
                "maturity_stage": item.get("maturity_stage"),
                "public_path": item.get("public_path"),
                "status": item.get("status"),
                "title": item.get("title"),
                "workflow_id": workflow_id,
            }
        )
    return rows


def build_pack(
    *,
    registry: dict[str, Any],
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    registry_path: Path,
    manifest_path: Path,
    policy_path: Path,
    registry_ref: Path,
    manifest_ref: Path,
    policy_ref: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    tiers = trust_tier_by_id(registry)
    connectors = [as_dict(connector, "connector") for connector in registry.get("connectors", [])]
    workflow_namespaces = {str(row.get("namespace")) for row in workflow_context_rows(manifest)}
    registry_namespaces = {str(connector.get("namespace")) for connector in connectors}
    missing_namespaces = sorted(workflow_namespaces - registry_namespaces)
    tier_counts = Counter(str(connector.get("trust_tier")) for connector in connectors)
    status_counts = Counter(str(connector.get("status")) for connector in connectors)
    access_counts = Counter(
        str(access)
        for connector in connectors
        for access in connector.get("access_modes", [])
    )
    coverage_percent = (
        round(
            100.0 * (len(workflow_namespaces - set(missing_namespaces)) / len(workflow_namespaces)),
            2,
        )
        if workflow_namespaces
        else 100.0
    )
    if float(coverage_percent).is_integer():
        coverage_percent = int(coverage_percent)

    return {
        "connector_trust_summary": {
            "access_mode_counts": dict(sorted(access_counts.items())),
            "approval_required_connector_count": access_counts.get("approval_required", 0),
            "connector_count": len(connectors),
            "failure_count": len(failures),
            "missing_workflow_namespaces": missing_namespaces,
            "production_connector_count": status_counts.get("production", 0),
            "registry_namespace_count": len(registry_namespaces),
            "scoped_write_connector_count": access_counts.get("write_branch", 0) + access_counts.get("write_ticket", 0),
            "status_counts": dict(sorted(status_counts.items())),
            "tier_counts": dict(sorted(tier_counts.items())),
            "workflow_namespace_count": len(workflow_namespaces),
            "workflow_namespace_coverage_percent": coverage_percent,
        },
        "connectors": [connector_summary(connector, tiers) for connector in sorted(connectors, key=lambda item: str(item.get("namespace")))],
        "enterprise_adoption_packet": {
            "board_level_claim": "Every MCP connector used by agentic remediation is inventoried, risk-tiered, and tied to enforceable controls before the agent can use it.",
            "default_questions_answered": [
                "Which MCP namespaces can approved workflows call?",
                "Which connectors are read-only, scoped-write, or approval-required?",
                "Which auth and token rules prevent confused-deputy and token-passthrough failures?",
                "Which connector evidence records prove calls stayed inside scope?",
                "Which kill signals stop a connector session when runtime behavior is unsafe?"
            ],
            "recommended_first_use": "Attach this trust pack to AI platform intake, MCP gateway design review, and enterprise connector promotion reviews.",
            "sales_motion": "Lead with open registry controls, then sell hosted gateway policy, connector trust telemetry, premium connector attestations, and customer-specific evidence exports."
        },
        "failures": failures,
        "generated_at": generated_at or str(registry.get("last_reviewed", "")),
        "global_control_objectives": registry.get("global_control_objectives", []),
        "intent": registry.get("intent"),
        "policy_alignment": {
            "gateway_default_decision": policy_pack.get("decision_contract", {}).get("default_decision"),
            "gateway_policy_id": policy_pack.get("policy_id"),
            "missing_workflow_namespaces": missing_namespaces,
            "policy_decisions": policy_pack.get("policy_summary", {}).get("policy_decisions", []),
            "source_manifest_hash_matches": policy_pack.get("source_manifest", {}).get("sha256") == sha256_file(manifest_path),
        },
        "positioning": registry.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "The registry proves declared controls, not live enforcement.",
                "treatment": "Bind the generated trust pack to the MCP gateway and export live deny, hold, and kill-session events as runtime evidence."
            },
            {
                "risk": "Vendor-hosted MCP servers can change tool descriptions or response behavior after approval.",
                "treatment": "Pin tool schemas, diff server cards or tool lists on update, and quarantine changed tool surfaces until reviewed."
            },
            {
                "risk": "Connector trust can drift as workflows add namespaces.",
                "treatment": "CI fails when workflow namespaces are not represented in the registry or access modes diverge from policy."
            }
        ],
        "schema_version": TRUST_PACK_SCHEMA_VERSION,
        "source_artifacts": {
            "connector_trust_registry": {
                "path": normalize_path(registry_ref),
                "sha256": sha256_file(registry_path),
            },
            "gateway_policy_pack": {
                "path": normalize_path(policy_ref),
                "sha256": sha256_file(policy_path),
            },
            "workflow_manifest": {
                "path": normalize_path(manifest_ref),
                "sha256": sha256_file(manifest_path),
            },
        },
        "standards_alignment": registry.get("standards_alignment", []),
        "trust_tiers": registry.get("trust_tiers", []),
        "workflow_connector_map": build_workflow_connector_map(
            manifest=manifest,
            registry=registry,
            policy_pack=policy_pack,
        ),
    }


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in trust pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    registry_path = resolve(repo_root, args.registry)
    manifest_path = resolve(repo_root, args.manifest)
    policy_path = resolve(repo_root, args.policy)
    output_path = resolve(repo_root, args.output)

    try:
        registry = load_json(registry_path)
        manifest = load_json(manifest_path)
        policy_pack = load_json(policy_path)
        failures = validate_registry(registry)
        failures.extend(
            validate_manifest_policy_alignment(
                registry=registry,
                manifest=manifest,
                policy_pack=policy_pack,
                manifest_path=manifest_path,
            )
        )
        pack = build_pack(
            registry=registry,
            manifest=manifest,
            policy_pack=policy_pack,
            registry_path=registry_path,
            manifest_path=manifest_path,
            policy_path=policy_path,
            registry_ref=args.registry,
            manifest_ref=args.manifest,
            policy_ref=args.policy,
            generated_at=args.generated_at,
            failures=failures,
        )
    except TrustPackError as exc:
        print(f"MCP connector trust pack generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)
    if args.check:
        if failures:
            print("MCP connector trust pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(
                f"{output_path} is stale; run scripts/generate_mcp_connector_trust_pack.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated MCP connector trust pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated MCP connector trust pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated MCP connector trust pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
