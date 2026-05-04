#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic approval receipt pack.

The pack turns human approvals into scope-bound receipts that can be
validated before high-impact agent actions execute. It joins action
runtime classes, run receipts, telemetry, entitlement review, gateway
policy, identity, and elicitation evidence into a deterministic artifact.
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
DEFAULT_PROFILE = Path("data/assurance/agentic-approval-receipt-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-approval-receipt-pack.json")

SOURCE_REFS = {
    "agent_identity_ledger": Path("data/evidence/agent-identity-delegation-ledger.json"),
    "agentic_action_runtime_pack": Path("data/evidence/agentic-action-runtime-pack.json"),
    "agentic_catastrophic_risk_annex": Path("data/evidence/agentic-catastrophic-risk-annex.json"),
    "agentic_entitlement_review_pack": Path("data/evidence/agentic-entitlement-review-pack.json"),
    "agentic_run_receipt_pack": Path("data/evidence/agentic-run-receipt-pack.json"),
    "agentic_telemetry_contract": Path("data/evidence/agentic-telemetry-contract.json"),
    "mcp_elicitation_boundary_pack": Path("data/evidence/mcp-elicitation-boundary-pack.json"),
    "mcp_gateway_policy": Path("data/policy/mcp-gateway-policy.json"),
}


class ApprovalReceiptPackError(RuntimeError):
    """Raised when approval receipt pack generation fails."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ApprovalReceiptPackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ApprovalReceiptPackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ApprovalReceiptPackError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ApprovalReceiptPackError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ApprovalReceiptPackError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must describe approval receipts")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 7, failures, "standards_alignment must include current primary references")
    seen_standards: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in seen_standards, failures, f"{standard_id}: duplicate standard id")
        seen_standards.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 60, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("approval_contract"), "approval_contract")
    require(
        contract.get("default_state")
        == "approval_untrusted_until_scope_authority_reviewer_separation_expiry_risk_acceptance_and_receipt_hash_are_bound",
        failures,
        "approval_contract.default_state must fail closed",
    )
    required_sources = {str(item) for item in as_list(contract.get("required_evidence_sources"), "approval_contract.required_evidence_sources")}
    require(len(required_sources) >= int(contract.get("minimum_required_evidence_sources") or 0), failures, "required evidence source count below minimum")
    require(not sorted(required_sources - set(SOURCE_REFS)), failures, "approval_contract contains unknown evidence sources")
    require(len(as_list(contract.get("required_runtime_fields"), "approval_contract.required_runtime_fields")) >= 16, failures, "runtime fields are incomplete")
    require(len(as_list(contract.get("decisions"), "approval_contract.decisions")) >= 7, failures, "decision ladder is incomplete")

    profiles = as_list(profile.get("approval_profiles"), "approval_profiles")
    require(len(profiles) >= int(contract.get("minimum_approval_profiles") or 0), failures, "approval profile count below minimum")
    seen_profiles: set[str] = set()
    mapped_action_classes: set[str] = set()
    for idx, approval in enumerate(profiles):
        item = as_dict(approval, f"approval_profiles[{idx}]")
        profile_id = str(item.get("id", "")).strip()
        require(bool(profile_id), failures, f"approval_profiles[{idx}].id is required")
        require(profile_id not in seen_profiles, failures, f"{profile_id}: duplicate approval profile")
        seen_profiles.add(profile_id)
        require(str(item.get("risk_tier")) in {"low", "medium", "high", "critical"}, failures, f"{profile_id}: invalid risk_tier")
        require(int(item.get("minimum_approvers") or 0) >= 1, failures, f"{profile_id}: minimum_approvers must be >= 1")
        require(str(item.get("role_policy")) in {"all_required", "at_least_one"}, failures, f"{profile_id}: invalid role_policy")
        require(int(item.get("max_ttl_minutes") or 0) > 0, failures, f"{profile_id}: max_ttl_minutes must be positive")
        require(isinstance(item.get("requires_risk_acceptance"), bool), failures, f"{profile_id}: requires_risk_acceptance must be boolean")
        require(isinstance(item.get("requires_separation_of_duties"), bool), failures, f"{profile_id}: requires_separation_of_duties must be boolean")
        require(bool(as_list(item.get("action_class_ids"), f"{profile_id}.action_class_ids")), failures, f"{profile_id}: action_class_ids are required")
        require(bool(as_list(item.get("required_roles"), f"{profile_id}.required_roles")), failures, f"{profile_id}: required_roles are required")
        require(len(as_list(item.get("scope_binding_fields"), f"{profile_id}.scope_binding_fields")) >= 5, failures, f"{profile_id}: scope binding is incomplete")
        mapped_action_classes.update(str(action) for action in item.get("action_class_ids", []))

    runtime_policy = as_dict(profile.get("runtime_policy"), "runtime_policy")
    require("approved" in as_list(runtime_policy.get("trusted_status_values"), "runtime_policy.trusted_status_values"), failures, "trusted statuses must include approved")
    require(len(as_list(runtime_policy.get("trusted_sources"), "runtime_policy.trusted_sources")) >= 3, failures, "trusted approval sources are incomplete")
    require(len(as_list(runtime_policy.get("kill_signal_indicators"), "runtime_policy.kill_signal_indicators")) >= 5, failures, "kill indicators are incomplete")
    require("repo_branch_write" in mapped_action_classes, failures, "repo_branch_write must map to an approval profile")
    require("funds_or_irreversible_transaction" in mapped_action_classes, failures, "irreversible transactions must map to an approval profile")

    buyer_views = as_list(profile.get("buyer_views"), "buyer_views")
    require(len(buyer_views) >= 3, failures, "buyer_views must include platform, IAM/GRC, and diligence")
    return failures


def load_sources(repo_root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    payloads: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for source_id, ref in SOURCE_REFS.items():
        path = resolve(repo_root, ref)
        try:
            payloads[source_id] = load_json(path)
        except ApprovalReceiptPackError as exc:
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


def source_artifacts(repo_root: Path, payloads: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
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


def action_classes(payloads: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = payloads.get("agentic_action_runtime_pack", {}).get("action_classes", [])
    return [row for row in rows if isinstance(row, dict)]


def workflow_action_matrix(payloads: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = payloads.get("agentic_action_runtime_pack", {}).get("workflow_action_matrix", [])
    return [row for row in rows if isinstance(row, dict)]


def receipt_template_by_workflow(payloads: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    rows = payloads.get("agentic_run_receipt_pack", {}).get("workflow_receipt_templates", [])
    return {
        str(row.get("workflow_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("workflow_id")
    }


def profile_by_action(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    by_action: dict[str, dict[str, Any]] = {}
    for approval_profile in profile.get("approval_profiles", []):
        if not isinstance(approval_profile, dict):
            continue
        for action_id in approval_profile.get("action_class_ids", []):
            by_action[str(action_id)] = approval_profile
    return by_action


def build_approval_profiles(profile: dict[str, Any], payloads: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    action_by_id = {str(row.get("id")): row for row in action_classes(payloads) if row.get("id")}
    profiles: list[dict[str, Any]] = []
    for approval_profile in profile.get("approval_profiles", []):
        if not isinstance(approval_profile, dict):
            continue
        actions = [
            {
                "action_class_id": action_id,
                "action_title": action_by_id.get(str(action_id), {}).get("title"),
                "action_risk_tier": action_by_id.get(str(action_id), {}).get("risk_tier"),
                "action_default_decision": action_by_id.get(str(action_id), {}).get("default_decision"),
            }
            for action_id in approval_profile.get("action_class_ids", [])
        ]
        profiles.append(
            {
                **approval_profile,
                "action_classes": actions,
                "approval_profile_hash": stable_hash(
                    {
                        "action_class_ids": approval_profile.get("action_class_ids", []),
                        "id": approval_profile.get("id"),
                        "minimum_approvers": approval_profile.get("minimum_approvers"),
                        "required_roles": approval_profile.get("required_roles", []),
                        "scope_binding_fields": approval_profile.get("scope_binding_fields", []),
                    }
                ),
            }
        )
    return profiles


def build_workflow_matrix(profile: dict[str, Any], payloads: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    by_action = profile_by_action(profile)
    receipt_by_workflow = receipt_template_by_workflow(payloads)
    rows: list[dict[str, Any]] = []
    for workflow in sorted(workflow_action_matrix(payloads), key=lambda row: str(row.get("workflow_id"))):
        workflow_id = str(workflow.get("workflow_id"))
        receipt = receipt_by_workflow.get(workflow_id, {})
        actions: list[dict[str, Any]] = []
        for action_id in workflow.get("action_class_ids", []):
            approval_profile = by_action.get(str(action_id), {})
            actions.append(
                {
                    "action_class_id": action_id,
                    "approval_profile_id": approval_profile.get("id"),
                    "default_decision": approval_profile.get("default_decision"),
                    "max_ttl_minutes": approval_profile.get("max_ttl_minutes"),
                    "minimum_approvers": approval_profile.get("minimum_approvers"),
                    "requires_risk_acceptance": approval_profile.get("requires_risk_acceptance"),
                    "required_roles": approval_profile.get("required_roles", []),
                    "risk_tier": approval_profile.get("risk_tier"),
                    "scope_binding_fields": approval_profile.get("scope_binding_fields", []),
                }
            )
        rows.append(
            {
                "action_approval_requirements": actions,
                "approval_required_action_count": sum(1 for action in actions if action.get("minimum_approvers")),
                "context_package_hash": receipt.get("context_package_hash"),
                "decision_floor": workflow.get("decision_floor"),
                "maturity_stage": workflow.get("maturity_stage"),
                "mcp_namespaces": workflow.get("mcp_namespaces", []),
                "receipt_id": receipt.get("receipt_id"),
                "receipt_status": receipt.get("receipt_status"),
                "title": workflow.get("title"),
                "workflow_id": workflow_id,
            }
        )
    return rows


def build_summary(
    approval_profiles: list[dict[str, Any]],
    workflow_matrix: list[dict[str, Any]],
    failures: list[str],
) -> dict[str, Any]:
    profile_risks = Counter(str(row.get("risk_tier")) for row in approval_profiles)
    decisions = Counter(str(row.get("default_decision")) for row in approval_profiles)
    action_ids = {
        str(action.get("action_class_id"))
        for profile in approval_profiles
        for action in profile.get("action_classes", [])
        if action.get("action_class_id")
    }
    return {
        "approval_profile_count": len(approval_profiles),
        "approval_required_workflow_count": sum(1 for row in workflow_matrix if row.get("approval_required_action_count")),
        "decision_counts": dict(sorted(decisions.items())),
        "distinct_action_class_count": len(action_ids),
        "failure_count": len(failures),
        "high_or_critical_profile_count": profile_risks.get("high", 0) + profile_risks.get("critical", 0),
        "profile_risk_counts": dict(sorted(profile_risks.items())),
        "status": "approval_receipt_ready" if not failures else "needs_attention",
        "workflow_count": len(workflow_matrix),
    }


def build_pack(
    *,
    profile: dict[str, Any],
    payloads: dict[str, dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    approval_profiles = build_approval_profiles(profile, payloads)
    workflow_matrix = build_workflow_matrix(profile, payloads)
    return {
        "approval_contract": profile.get("approval_contract", {}),
        "approval_profiles": approval_profiles,
        "approval_receipt_pack_id": "security-recipes.agentic-approval-receipts.v1",
        "approval_receipt_summary": build_summary(approval_profiles, workflow_matrix, failures),
        "buyer_views": profile.get("buyer_views", []),
        "commercialization_path": profile.get("commercialization_path", {}),
        "enterprise_adoption_packet": {
            "board_level_claim": profile.get("executive_readout", {}).get("board_level_claim"),
            "default_questions_answered": [
                "Which approval profile governs this action class?",
                "How many approvers and which roles are required?",
                "Is the approval scope-bound to this workflow, run, tenant, identity, and action?",
                "Does the approval expire before execution?",
                "Is risk acceptance required before the agent proceeds?"
            ],
            "recommended_first_use": profile.get("executive_readout", {}).get("recommended_first_use"),
            "sales_motion": profile.get("executive_readout", {}).get("sales_motion"),
        },
        "executive_readout": profile.get("executive_readout", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "The open pack validates approval receipt shape, but production enforcement still needs source-host, ITSM, IAM, and MCP gateway integration.",
                "treatment": "Hosted deployments should verify approval source signatures, actor identities, tenant boundaries, and receipt hashes before forwarding privileged tool calls."
            },
            {
                "risk": "A valid approval can still be unsafe if the approved scope is broader than the actual business intent.",
                "treatment": "Bind approvals to stable scope hashes and regenerate them after changed paths, data classes, namespaces, release artifacts, or target resources drift."
            },
            {
                "risk": "Approval fatigue can normalize high-risk agent actions.",
                "treatment": "Use profile TTLs, two-key review, risk acceptance, and red-team replay to keep approval volume and bypass attempts visible."
            }
        ],
        "runtime_policy": profile.get("runtime_policy", {}),
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": artifacts,
        "standards_alignment": profile.get("standards_alignment", []),
        "workflow_approval_matrix": workflow_matrix,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in approval receipt pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        payloads, load_failures = load_sources(repo_root)
        artifacts = source_artifacts(repo_root, payloads)
        failures = [
            *validate_profile(profile),
            *load_failures,
            *validate_sources(payloads),
        ]
        pack = build_pack(
            profile=profile,
            payloads=payloads,
            artifacts=artifacts,
            generated_at=args.generated_at,
            failures=failures,
        )
    except ApprovalReceiptPackError as exc:
        print(f"agentic approval receipt pack generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("agentic approval receipt pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_agentic_approval_receipt_pack.py", file=sys.stderr)
            return 1
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_agentic_approval_receipt_pack.py", file=sys.stderr)
            return 1
        print(f"Validated agentic approval receipt pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated agentic approval receipt pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated agentic approval receipt pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
