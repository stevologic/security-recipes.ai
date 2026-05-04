#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic entitlement review pack.

The pack converts non-human agent identities into expiring, reviewable,
revocable entitlements. It is deliberately deterministic so CI can prove
that identity, MCP authorization, connector trust, A2A handoff, runtime
action, telemetry, and receipt evidence did not drift from the generated
access-review surface.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PACK_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/agentic-entitlement-review-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-entitlement-review-pack.json")

SOURCE_REFS = {
    "a2a_agent_card_trust_profile": Path("data/evidence/a2a-agent-card-trust-profile.json"),
    "agent_handoff_boundary_pack": Path("data/evidence/agent-handoff-boundary-pack.json"),
    "agent_identity_ledger": Path("data/evidence/agent-identity-delegation-ledger.json"),
    "agentic_action_runtime_pack": Path("data/evidence/agentic-action-runtime-pack.json"),
    "agentic_run_receipt_pack": Path("data/evidence/agentic-run-receipt-pack.json"),
    "agentic_telemetry_contract": Path("data/evidence/agentic-telemetry-contract.json"),
    "mcp_authorization_conformance": Path("data/evidence/mcp-authorization-conformance-pack.json"),
    "mcp_connector_trust_pack": Path("data/evidence/mcp-connector-trust-pack.json"),
    "mcp_gateway_policy": Path("data/policy/mcp-gateway-policy.json"),
}


class EntitlementReviewPackError(RuntimeError):
    """Raised when the entitlement review pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise EntitlementReviewPackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise EntitlementReviewPackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise EntitlementReviewPackError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EntitlementReviewPackError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise EntitlementReviewPackError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must describe entitlement review")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 6, failures, "standards_alignment must include OWASP, MCP, A2A, Microsoft, OpenAI, and NIST references")
    seen_standards: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in seen_standards, failures, f"{standard_id}: duplicate standard id")
        seen_standards.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 60, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("review_contract"), "review_contract")
    require(
        contract.get("default_state")
        == "entitlement_inactive_until_identity_scope_lease_review_authorization_and_receipt_evidence_are_bound",
        failures,
        "review_contract.default_state must fail closed",
    )
    require(len(as_list(contract.get("required_runtime_fields"), "review_contract.required_runtime_fields")) >= 12, failures, "runtime fields are incomplete")
    required_sources = {str(item) for item in as_list(contract.get("required_evidence_sources"), "review_contract.required_evidence_sources")}
    require(len(required_sources) >= int(contract.get("minimum_required_evidence_sources") or 0), failures, "required evidence source count below minimum")
    require(not sorted(required_sources - set(SOURCE_REFS)), failures, "review_contract contains unknown evidence sources")
    require(len(as_list(contract.get("decisions"), "review_contract.decisions")) >= 6, failures, "decision ladder is incomplete")

    tiers = as_list(profile.get("entitlement_tiers"), "entitlement_tiers")
    require(len(tiers) >= int(contract.get("minimum_entitlement_tiers") or 0), failures, "entitlement tier count below minimum")
    seen_tiers: set[str] = set()
    for idx, tier in enumerate(tiers):
        item = as_dict(tier, f"entitlement_tiers[{idx}]")
        tier_id = str(item.get("id", "")).strip()
        require(bool(tier_id), failures, f"entitlement_tiers[{idx}].id is required")
        require(tier_id not in seen_tiers, failures, f"{tier_id}: duplicate entitlement tier")
        seen_tiers.add(tier_id)
        require(str(item.get("risk_tier")) in {"low", "medium", "high", "critical"}, failures, f"{tier_id}: invalid risk_tier")
        require(isinstance(item.get("requires_human_approval"), bool), failures, f"{tier_id}: requires_human_approval must be boolean")
        require(isinstance(item.get("lease_ttl_days"), int), failures, f"{tier_id}: lease_ttl_days must be integer")
        require(isinstance(item.get("review_cadence_days"), int), failures, f"{tier_id}: review_cadence_days must be integer")
        require(bool(as_list(item.get("applies_to_access_modes"), f"{tier_id}.applies_to_access_modes")), failures, f"{tier_id}: access modes are required")
        require(len(as_list(item.get("required_evidence"), f"{tier_id}.required_evidence")) >= 5, failures, f"{tier_id}: evidence requirements are incomplete")

    runtime_policy = as_dict(profile.get("runtime_policy"), "runtime_policy")
    require("active" in as_list(runtime_policy.get("lease_status_values"), "runtime_policy.lease_status_values"), failures, "lease status values must include active")
    require("allow" in as_list(runtime_policy.get("authorization_allow_prefixes"), "runtime_policy.authorization_allow_prefixes"), failures, "authorization allow prefixes must include allow")
    require(len(as_list(runtime_policy.get("kill_signal_indicators"), "runtime_policy.kill_signal_indicators")) >= 5, failures, "kill indicators are incomplete")

    buyer_views = as_list(profile.get("buyer_views"), "buyer_views")
    require(len(buyer_views) >= 3, failures, "buyer_views must include IAM, MCP gateway, and diligence views")
    return failures


def load_sources(repo_root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    payloads: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for source_id, ref in SOURCE_REFS.items():
        path = resolve(repo_root, ref)
        try:
            payloads[source_id] = load_json(path)
        except EntitlementReviewPackError as exc:
            failures.append(f"{source_id}: {exc}")
    return payloads, failures


def validate_sources(payloads: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    missing = sorted(set(SOURCE_REFS) - set(payloads))
    require(not missing, failures, f"missing source payloads: {missing}")
    for source_id, payload in payloads.items():
        require(payload.get("schema_version") == PACK_SCHEMA_VERSION, failures, f"{source_id} schema_version must be 1.0")
        source_failures = payload.get("failures")
        if isinstance(source_failures, list) and source_failures:
            failures.extend(f"{source_id}: {failure}" for failure in source_failures)
    return failures


def build_source_artifacts(repo_root: Path, payloads: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    artifacts: dict[str, dict[str, Any]] = {}
    for source_id, ref in SOURCE_REFS.items():
        path = resolve(repo_root, ref)
        payload = payloads.get(source_id, {})
        failures = payload.get("failures") if isinstance(payload, dict) else []
        artifacts[source_id] = {
            "failure_count": len(failures) if isinstance(failures, list) else 0,
            "path": normalize_path(ref),
            "schema_version": payload.get("schema_version") if isinstance(payload, dict) else None,
            "sha256": sha256_file(path) if path.exists() else None,
            "summary_keys": sorted(
                key for key, value in payload.items()
                if isinstance(value, dict) and key.endswith("_summary")
            ) if isinstance(payload, dict) else [],
        }
    return artifacts


def tier_by_access(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    by_access: dict[str, dict[str, Any]] = {}
    for tier in profile.get("entitlement_tiers", []):
        if not isinstance(tier, dict):
            continue
        for mode in tier.get("applies_to_access_modes", []):
            by_access[str(mode)] = tier
    return by_access


def identities(payloads: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = payloads.get("agent_identity_ledger", {}).get("agent_identities", [])
    return [row for row in rows if isinstance(row, dict)]


def action_matrix_by_workflow(payloads: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    matrix = payloads.get("agentic_action_runtime_pack", {}).get("workflow_action_matrix", [])
    return {
        str(row.get("workflow_id")): row
        for row in matrix
        if isinstance(row, dict) and row.get("workflow_id")
    }


def connector_trust_by_namespace(payloads: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    pack = payloads.get("mcp_connector_trust_pack", {})
    rows = []
    for key in ["connector_trust", "connectors", "namespace_trust"]:
        value = pack.get(key)
        if isinstance(value, list):
            rows.extend(row for row in value if isinstance(row, dict))
    output: dict[str, dict[str, Any]] = {}
    for row in rows:
        namespace = row.get("namespace") or row.get("mcp_namespace")
        if namespace:
            output[str(namespace)] = row
    return output


def entitlement_tier_for_scope(scope: dict[str, Any], identity: dict[str, Any], tiers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    access = str(scope.get("access", ""))
    if scope.get("decision") == "hold_for_approval":
        return tiers["approval_required"]
    if identity.get("risk_tier") == "high-control" and access.startswith("write"):
        return tiers["approval_required"]
    return tiers.get(access, tiers["read"])


def entitlement_id(identity_id: str, namespace: str, access: str) -> str:
    digest = stable_hash({"access": access, "identity_id": identity_id, "namespace": namespace})[:12]
    return f"sr-entitlement::{digest}"


def approval_namespaces(identity: dict[str, Any]) -> set[str]:
    authority = identity.get("delegated_authority") if isinstance(identity.get("delegated_authority"), dict) else {}
    return {str(item) for item in authority.get("approval_required_namespaces", [])}


def build_entitlements(profile: dict[str, Any], payloads: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    tiers = tier_by_access(profile)
    action_by_workflow = action_matrix_by_workflow(payloads)
    connector_by_namespace = connector_trust_by_namespace(payloads)
    entitlements: list[dict[str, Any]] = []

    for identity in sorted(identities(payloads), key=lambda row: str(row.get("identity_id"))):
        authority = identity.get("delegated_authority") if isinstance(identity.get("delegated_authority"), dict) else {}
        scopes = [
            scope
            for scope in authority.get("mcp_scopes", [])
            if isinstance(scope, dict) and scope.get("namespace") and scope.get("access")
        ]
        approvals = approval_namespaces(identity)
        workflow_id = str(identity.get("workflow_id"))
        action_matrix = action_by_workflow.get(workflow_id, {})
        for scope in sorted(scopes, key=lambda row: f"{row.get('namespace')}::{row.get('access')}"):
            namespace = str(scope.get("namespace"))
            access = str(scope.get("access"))
            tier = entitlement_tier_for_scope(scope, identity, tiers)
            owner = identity.get("owner") if isinstance(identity.get("owner"), dict) else {}
            requires_approval = bool(tier.get("requires_human_approval")) or namespace in approvals
            entitlements.append(
                {
                    "access_mode": access,
                    "agent_class": identity.get("agent_class"),
                    "authorization_expectations": {
                        "audience_bound_token_required": True,
                        "mcp_resource_indicator_required": True,
                        "pkce_required_for_user_authorization": True,
                        "scope_challenge_supported": True,
                        "token_passthrough_forbidden": True,
                    },
                    "connector_trust": connector_by_namespace.get(namespace, {}),
                    "default_decision": "hold_for_access_review" if requires_approval else "allow_active_entitlement",
                    "entitlement_hash": stable_hash(
                        {
                            "access": access,
                            "identity_id": identity.get("identity_id"),
                            "namespace": namespace,
                            "workflow_id": workflow_id,
                        }
                    ),
                    "entitlement_id": entitlement_id(str(identity.get("identity_id")), namespace, access),
                    "identity_id": identity.get("identity_id"),
                    "kill_signals": sorted(
                        {
                            *[str(item) for item in identity.get("runtime_contract", {}).get("kill_signals", [])],
                            *[str(item) for item in profile.get("runtime_policy", {}).get("kill_signal_indicators", [])],
                        }
                    ),
                    "lease_ttl_days": tier.get("lease_ttl_days"),
                    "linked_action_class_ids": action_matrix.get("action_class_ids", []),
                    "linked_mcp_tools": sorted(
                        {
                            "recipes_agent_identity_ledger",
                            "recipes_mcp_authorization_conformance_pack",
                            "recipes_evaluate_mcp_authorization_decision",
                            "recipes_agentic_entitlement_review_pack",
                            "recipes_evaluate_agentic_entitlement_decision",
                            *[str(tool) for tool in action_matrix.get("mcp_tools", [])],
                        }
                    ),
                    "namespace": namespace,
                    "owner": {
                        "accountable_team": owner.get("accountable_team"),
                        "escalation": owner.get("escalation"),
                        "reviewer_pools": owner.get("reviewer_pools", []),
                    },
                    "purpose": scope.get("purpose"),
                    "required_evidence": tier.get("required_evidence", []),
                    "requires_human_approval": requires_approval,
                    "review_cadence_days": tier.get("review_cadence_days"),
                    "risk_tier": tier.get("risk_tier"),
                    "source_identity_risk_tier": identity.get("risk_tier"),
                    "status": identity.get("status"),
                    "tier_id": tier.get("id"),
                    "tier_title": tier.get("title"),
                    "workflow_id": workflow_id,
                    "workflow_title": identity.get("workflow_title"),
                }
            )
    return entitlements


def build_workflow_rollups(entitlements: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_workflow: dict[str, list[dict[str, Any]]] = {}
    for entitlement in entitlements:
        by_workflow.setdefault(str(entitlement.get("workflow_id")), []).append(entitlement)

    rows: list[dict[str, Any]] = []
    for workflow_id in sorted(by_workflow):
        items = by_workflow[workflow_id]
        risk_counts = Counter(str(item.get("risk_tier")) for item in items)
        access_modes = sorted({str(item.get("access_mode")) for item in items})
        namespaces = sorted({str(item.get("namespace")) for item in items})
        rows.append(
            {
                "access_modes": access_modes,
                "approval_required_entitlement_count": sum(1 for item in items if item.get("requires_human_approval")),
                "entitlement_count": len(items),
                "identity_count": len({str(item.get("identity_id")) for item in items}),
                "namespace_count": len(namespaces),
                "namespaces": namespaces,
                "risk_counts": dict(sorted(risk_counts.items())),
                "workflow_id": workflow_id,
                "workflow_title": items[0].get("workflow_title"),
            }
        )
    return rows


def build_summary(entitlements: list[dict[str, Any]], failures: list[str]) -> dict[str, Any]:
    risk_counts = Counter(str(item.get("risk_tier")) for item in entitlements)
    access_counts = Counter(str(item.get("access_mode")) for item in entitlements)
    tier_counts = Counter(str(item.get("tier_id")) for item in entitlements)
    return {
        "access_mode_counts": dict(sorted(access_counts.items())),
        "approval_required_entitlement_count": sum(1 for item in entitlements if item.get("requires_human_approval")),
        "distinct_identity_count": len({str(item.get("identity_id")) for item in entitlements}),
        "entitlement_count": len(entitlements),
        "failure_count": len(failures),
        "high_or_critical_entitlement_count": risk_counts.get("high", 0) + risk_counts.get("critical", 0),
        "risk_counts": dict(sorted(risk_counts.items())),
        "status": "entitlement_review_ready" if not failures else "needs_attention",
        "tier_counts": dict(sorted(tier_counts.items())),
        "workflow_count": len({str(item.get("workflow_id")) for item in entitlements}),
    }


def build_pack(
    *,
    profile: dict[str, Any],
    payloads: dict[str, dict[str, Any]],
    source_artifacts: dict[str, dict[str, Any]],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    entitlements = build_entitlements(profile, payloads)
    return {
        "buyer_views": profile.get("buyer_views", []),
        "commercialization_path": profile.get("commercialization_path", {}),
        "enterprise_adoption_packet": {
            "board_level_claim": profile.get("executive_readout", {}).get("board_level_claim"),
            "default_questions_answered": [
                "Which agent entitlements exist?",
                "Which MCP namespaces and access modes does each identity hold?",
                "Which entitlements require approval or step-up authorization?",
                "When should access be allowed, held, denied, or killed?",
                "Which evidence packs and MCP tools explain the decision?"
            ],
            "recommended_first_use": profile.get("executive_readout", {}).get("recommended_first_use"),
            "sales_motion": "Lead with open entitlement evidence, then sell hosted permission leases, access-review automation, IdP adapters, approval receipts, and MCP gateway enforcement APIs."
        },
        "entitlement_review_pack_id": "security-recipes.agentic-entitlement-review.v1",
        "entitlement_review_summary": build_summary(entitlements, failures),
        "entitlements": entitlements,
        "executive_readout": profile.get("executive_readout", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "The open pack models entitlements and decisions, but production enforcement still needs IdP, MCP gateway, approval-system, and agent-host integration.",
                "treatment": "Bind runtime credentials to entitlement_id, lease_id, run_id, tenant_id, authorization decision, approval records, and receipt evidence before forwarding MCP calls."
            },
            {
                "risk": "Static leases can drift from real customer IAM or source-host state.",
                "treatment": "Use hosted evidence ingestion and revocation webhooks to reconcile IdP groups, service principals, source-host permissions, and MCP scopes continuously."
            },
            {
                "risk": "Human access reviews can miss model, connector, and context drift.",
                "treatment": "Trigger entitlement review after model upgrades, connector drift, Agent Card changes, incident replay, new action classes, or standards-crosswalk changes."
            }
        ],
        "review_contract": profile.get("review_contract", {}),
        "runtime_policy": profile.get("runtime_policy", {}),
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": source_artifacts,
        "standards_alignment": profile.get("standards_alignment", []),
        "workflow_entitlement_rollups": build_workflow_rollups(entitlements),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in entitlement review pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        source_payloads, load_failures = load_sources(repo_root)
        source_artifacts = build_source_artifacts(repo_root, source_payloads)
        failures = [
            *validate_profile(profile),
            *load_failures,
            *validate_sources(source_payloads),
        ]
        pack = build_pack(
            profile=profile,
            payloads=source_payloads,
            source_artifacts=source_artifacts,
            generated_at=args.generated_at,
            failures=failures,
        )
    except EntitlementReviewPackError as exc:
        print(f"agentic entitlement review pack generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("agentic entitlement review pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_agentic_entitlement_review_pack.py", file=sys.stderr)
            return 1
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_agentic_entitlement_review_pack.py", file=sys.stderr)
            return 1
        print(f"Validated agentic entitlement review pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated agentic entitlement review pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated agentic entitlement review pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
