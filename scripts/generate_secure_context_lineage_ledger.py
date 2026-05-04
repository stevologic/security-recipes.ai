#!/usr/bin/env python3
"""Generate the SecurityRecipes secure context lineage ledger.

The ledger makes the secure context layer inspectable as context moves
through an agent run: registered source, hash, attestation, poisoning
scan, retrieval policy, model route, egress boundary, handoff boundary,
telemetry, and sealed run receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/secure-context-lineage-profile.json")
DEFAULT_CONTEXT_TRUST_PACK = Path("data/evidence/secure-context-trust-pack.json")
DEFAULT_CONTEXT_ATTESTATION_PACK = Path("data/evidence/secure-context-attestation-pack.json")
DEFAULT_CONTEXT_POISONING_GUARD_PACK = Path("data/evidence/context-poisoning-guard-pack.json")
DEFAULT_CONTEXT_EGRESS_BOUNDARY_PACK = Path("data/evidence/context-egress-boundary-pack.json")
DEFAULT_HANDOFF_BOUNDARY_PACK = Path("data/evidence/agent-handoff-boundary-pack.json")
DEFAULT_TELEMETRY_CONTRACT = Path("data/evidence/agentic-telemetry-contract.json")
DEFAULT_RUN_RECEIPT_PACK = Path("data/evidence/agentic-run-receipt-pack.json")
DEFAULT_MODEL_PROVIDER_ROUTING_PACK = Path("data/evidence/model-provider-routing-pack.json")
DEFAULT_OUTPUT = Path("data/evidence/secure-context-lineage-ledger.json")

SOURCE_PACK_REFS = {
    "secure_context_trust_pack": DEFAULT_CONTEXT_TRUST_PACK,
    "secure_context_attestation_pack": DEFAULT_CONTEXT_ATTESTATION_PACK,
    "context_poisoning_guard_pack": DEFAULT_CONTEXT_POISONING_GUARD_PACK,
    "context_egress_boundary_pack": DEFAULT_CONTEXT_EGRESS_BOUNDARY_PACK,
    "agent_handoff_boundary_pack": DEFAULT_HANDOFF_BOUNDARY_PACK,
    "agentic_telemetry_contract": DEFAULT_TELEMETRY_CONTRACT,
    "agentic_run_receipt_pack": DEFAULT_RUN_RECEIPT_PACK,
    "model_provider_routing_pack": DEFAULT_MODEL_PROVIDER_ROUTING_PACK,
}

KILL_DECISION = "kill_session_on_lineage_break"
HOLD_EVIDENCE_DECISION = "hold_for_lineage_evidence"
HOLD_POISONING_DECISION = "hold_for_poisoning_review"
ALLOW_DECISION = "allow_lineage_bound_context"


class SecureContextLineageError(RuntimeError):
    """Raised when the secure context lineage ledger cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SecureContextLineageError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SecureContextLineageError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SecureContextLineageError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SecureContextLineageError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SecureContextLineageError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def normalize_path(path: Path) -> str:
    return path.as_posix()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def index_by(rows: Any, key: str) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get(key)): row
        for row in rows
        if isinstance(row, dict) and row.get(key)
    }


def summary_failure_count(payload: dict[str, Any]) -> int:
    count = 0
    failures = payload.get("failures")
    if isinstance(failures, list):
        count += len(failures)
    for key, value in payload.items():
        if isinstance(value, dict) and key.endswith("_summary"):
            count += int(value.get("failure_count") or 0)
    return count


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must describe context lineage")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 8, failures, "standards_alignment must include current agentic AI and MCP references")
    seen_standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in seen_standard_ids, failures, f"{standard_id}: duplicate standard id")
        seen_standard_ids.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 60, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("lineage_contract"), "lineage_contract")
    require(contract.get("default_decision") == "deny_unbound_context_lineage", failures, "lineage default must fail closed")
    required_packs = {str(item) for item in as_list(contract.get("required_source_packs"), "lineage_contract.required_source_packs")}
    require(len(required_packs) >= int(contract.get("minimum_required_source_packs") or 0), failures, "too few required source packs")
    require(not sorted(required_packs - set(SOURCE_PACK_REFS)), failures, "profile references unknown source packs")
    require(len(as_list(contract.get("required_runtime_fields"), "lineage_contract.required_runtime_fields")) >= 18, failures, "runtime fields must bind source, route, egress, handoff, telemetry, and receipt evidence")

    stages = as_list(profile.get("lineage_stages"), "lineage_stages")
    required_stage_ids = {
        str(stage_id)
        for stage_id in as_list(contract.get("required_lineage_stage_ids"), "lineage_contract.required_lineage_stage_ids")
    }
    stage_ids: set[str] = set()
    for idx, stage in enumerate(stages):
        item = as_dict(stage, f"lineage_stages[{idx}]")
        stage_id = str(item.get("id", "")).strip()
        require(bool(stage_id), failures, f"lineage_stages[{idx}].id is required")
        require(stage_id not in stage_ids, failures, f"{stage_id}: duplicate stage id")
        stage_ids.add(stage_id)
        require(len(as_list(item.get("required_evidence"), f"{stage_id}.required_evidence")) >= 4, failures, f"{stage_id}: required_evidence is incomplete")
        require(len(as_list(item.get("hold_signals"), f"{stage_id}.hold_signals")) >= 2, failures, f"{stage_id}: hold_signals are incomplete")
        require(len(as_list(item.get("kill_signals"), f"{stage_id}.kill_signals")) >= 2, failures, f"{stage_id}: kill_signals are incomplete")
    require(required_stage_ids.issubset(stage_ids), failures, "lineage stages must include every required stage id")

    reuse_policy = as_dict(profile.get("reuse_policy"), "reuse_policy")
    reuse_classes = as_list(reuse_policy.get("allowed_reuse_classes"), "reuse_policy.allowed_reuse_classes")
    require(len(reuse_classes) >= 5, failures, "reuse policy must cover same-run, same-tenant, cross-workflow, cross-tenant, and public-corpus reuse")
    return failures


def validate_sources(sources: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    missing = sorted(set(SOURCE_PACK_REFS) - set(sources))
    require(not missing, failures, f"missing source packs: {missing}")
    for source_id, payload in sources.items():
        require(payload.get("schema_version") == SCHEMA_VERSION, failures, f"{source_id} schema_version must be 1.0")
        source_failures = summary_failure_count(payload)
        require(source_failures == 0, failures, f"{source_id} has {source_failures} source validation failure(s)")
    return failures


def source_artifacts(repo_root: Path, refs: dict[str, Path], sources: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    artifacts: dict[str, dict[str, Any]] = {}
    for source_id, ref in sorted(refs.items()):
        path = resolve(repo_root, ref)
        payload = sources.get(source_id, {})
        artifacts[source_id] = {
            "failure_count": summary_failure_count(payload) if isinstance(payload, dict) else 0,
            "path": normalize_path(ref),
            "schema_version": payload.get("schema_version") if isinstance(payload, dict) else None,
            "sha256": sha256_file(path) if path.exists() else None,
        }
    return artifacts


def trust_tier_id(source: dict[str, Any]) -> str:
    trust_tier = source.get("trust_tier")
    if isinstance(trust_tier, dict):
        return str(trust_tier.get("id") or "")
    return str(trust_tier or "")


def source_lineage_decision(source: dict[str, Any], attestation: dict[str, Any] | None, poisoning: dict[str, Any] | None) -> str:
    if trust_tier_id(source) == "tier_4_prohibited_context" or source.get("decision") == "kill_session_on_prohibited_context":
        return KILL_DECISION

    if attestation is None or str(attestation.get("decision")) not in {"allow_attested_context", "allow_attested_workflow_context"}:
        return HOLD_EVIDENCE_DECISION

    if poisoning:
        poisoning_decision = str(poisoning.get("decision") or "")
        actionable_count = int(poisoning.get("actionable_finding_count") or 0)
        if poisoning_decision == "block_until_removed" or actionable_count:
            return HOLD_POISONING_DECISION

    return ALLOW_DECISION


def allowed_reuse_classes_for_source(source: dict[str, Any]) -> list[str]:
    exposure = str(source.get("exposure") or "")
    tier = trust_tier_id(source)
    if exposure == "prohibited" or tier == "tier_4_prohibited_context":
        return []
    if exposure == "public" and tier in {"tier_0_public_reference", "tier_1_curated_guidance", "tier_2_policy_context"}:
        return ["same_run_context_replay", "cross_workflow_policy_reuse"]
    if exposure in {"tenant", "internal"}:
        return ["same_run_context_replay", "same_tenant_followup"]
    return ["same_run_context_replay"]


def build_source_lineage(sources: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    trust_sources = sources["secure_context_trust_pack"].get("context_sources", [])
    source_attestations = index_by(
        sources["secure_context_attestation_pack"].get("attestation_manifest", {}).get("context_source_attestations", []),
        "source_id",
    )
    poisoning_results = index_by(sources["context_poisoning_guard_pack"].get("source_results", []), "source_id")

    rows: list[dict[str, Any]] = []
    for source in trust_sources:
        if not isinstance(source, dict) or not source.get("source_id"):
            continue
        source_id = str(source["source_id"])
        attestation = source_attestations.get(source_id)
        poisoning = poisoning_results.get(source_id)
        rows.append(
            {
                "allowed_reuse_classes": allowed_reuse_classes_for_source(source),
                "attestation": {
                    "attestation_id": attestation.get("attestation_id") if attestation else None,
                    "decision": attestation.get("decision") if attestation else None,
                    "freshness_state": attestation.get("freshness_state") if attestation else None,
                    "recertification_due_days": attestation.get("recertification", {}).get("due_days") if attestation else None,
                },
                "citation_required": source.get("citation_required"),
                "decision": source_lineage_decision(source, attestation, poisoning),
                "exposure": source.get("exposure"),
                "instruction_handling": source.get("instruction_handling"),
                "lineage_break_signals": [
                    signal
                    for signal in [
                        "prohibited_context_source" if trust_tier_id(source) == "tier_4_prohibited_context" else "",
                        "missing_attestation" if attestation is None else "",
                        "actionable_poisoning_findings" if poisoning and int(poisoning.get("actionable_finding_count") or 0) else "",
                    ]
                    if signal
                ],
                "owner": source.get("owner", {}),
                "poisoning": {
                    "actionable_finding_count": poisoning.get("actionable_finding_count") if poisoning else None,
                    "decision": poisoning.get("decision") if poisoning else None,
                    "finding_count": poisoning.get("finding_count") if poisoning else None,
                    "risk_family_counts": poisoning.get("risk_family_counts") if poisoning else {},
                },
                "retrieval_decision": source.get("decision"),
                "retrieval_modes": source.get("retrieval_modes", []),
                "root": source.get("root"),
                "source_hash": source.get("source_hash"),
                "source_id": source_id,
                "title": source.get("title"),
                "trust_tier": trust_tier_id(source),
            }
        )
    return sorted(rows, key=lambda row: str(row["source_id"]))


def workflow_lineage_decision(
    workflow: dict[str, Any],
    source_rows: dict[str, dict[str, Any]],
    attestation: dict[str, Any] | None,
    telemetry: dict[str, Any] | None,
    receipt: dict[str, Any] | None,
) -> str:
    if workflow.get("status") != "active":
        return "deny_unbound_context_lineage"
    if attestation is None or attestation.get("decision") != "allow_attested_workflow_context":
        return HOLD_EVIDENCE_DECISION
    if telemetry is None or telemetry.get("decision") != "telemetry_ready":
        return HOLD_EVIDENCE_DECISION
    if receipt is None or not receipt.get("receipt_id"):
        return HOLD_EVIDENCE_DECISION

    source_ids = [str(source_id) for source_id in workflow.get("source_ids", []) or []]
    decisions = {str(source_rows.get(source_id, {}).get("decision")) for source_id in source_ids}
    if KILL_DECISION in decisions:
        return KILL_DECISION
    if HOLD_POISONING_DECISION in decisions:
        return HOLD_POISONING_DECISION
    if HOLD_EVIDENCE_DECISION in decisions:
        return HOLD_EVIDENCE_DECISION
    return ALLOW_DECISION


def stage_requirements(profile: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "id": stage.get("id"),
            "required_evidence": stage.get("required_evidence", []),
            "title": stage.get("title"),
        }
        for stage in profile.get("lineage_stages", [])
        if isinstance(stage, dict)
    ]


def build_workflow_lineage(profile: dict[str, Any], sources: dict[str, dict[str, Any]], source_lineage: list[dict[str, Any]]) -> list[dict[str, Any]]:
    workflow_contexts = sources["secure_context_trust_pack"].get("workflow_context_map", [])
    workflow_attestations = index_by(
        sources["secure_context_attestation_pack"].get("attestation_manifest", {}).get("workflow_context_package_attestations", []),
        "workflow_id",
    )
    egress_by_workflow = index_by(sources["context_egress_boundary_pack"].get("workflow_egress_map", []), "workflow_id")
    handoff_by_workflow = index_by(sources["agent_handoff_boundary_pack"].get("workflow_handoff_map", []), "workflow_id")
    telemetry_by_workflow = index_by(sources["agentic_telemetry_contract"].get("workflow_telemetry_contracts", []), "workflow_id")
    receipt_by_workflow = index_by(sources["agentic_run_receipt_pack"].get("workflow_receipt_templates", []), "workflow_id")
    route_by_workflow = index_by(sources["model_provider_routing_pack"].get("workflow_route_matrix", []), "workflow_id")
    source_by_id = {str(row["source_id"]): row for row in source_lineage}
    stage_rows = stage_requirements(profile)

    rows: list[dict[str, Any]] = []
    for workflow in workflow_contexts:
        if not isinstance(workflow, dict) or not workflow.get("workflow_id"):
            continue
        workflow_id = str(workflow["workflow_id"])
        attestation = workflow_attestations.get(workflow_id)
        egress = egress_by_workflow.get(workflow_id)
        handoff = handoff_by_workflow.get(workflow_id)
        telemetry = telemetry_by_workflow.get(workflow_id)
        receipt = receipt_by_workflow.get(workflow_id)
        route = route_by_workflow.get(workflow_id)
        source_ids = [str(source_id) for source_id in workflow.get("source_ids", []) or []]
        source_decisions = Counter(str(source_by_id.get(source_id, {}).get("decision")) for source_id in source_ids)

        approved_reuse_classes = {"same_run_context_replay"}
        if all("cross_workflow_policy_reuse" in source_by_id.get(source_id, {}).get("allowed_reuse_classes", []) for source_id in source_ids):
            approved_reuse_classes.add("cross_workflow_policy_reuse")
        if any("same_tenant_followup" in source_by_id.get(source_id, {}).get("allowed_reuse_classes", []) for source_id in source_ids):
            approved_reuse_classes.add("same_tenant_followup")

        rows.append(
            {
                "agent_classes": telemetry.get("agent_classes", []) if telemetry else workflow.get("agent_classes", []),
                "approved_reuse_classes": sorted(approved_reuse_classes),
                "attestation_decision": attestation.get("decision") if attestation else None,
                "context_package_hash": workflow.get("context_package_hash"),
                "decision": workflow_lineage_decision(workflow, source_by_id, attestation, telemetry, receipt),
                "egress_policy_hash": egress.get("egress_policy_hash") if egress else None,
                "handoff_default_decision": handoff.get("default_decision") if handoff else None,
                "lineage_stage_requirements": stage_rows,
                "maturity_stage": workflow.get("maturity_stage"),
                "mcp_namespaces": telemetry.get("mcp_namespaces", workflow.get("mcp_namespaces", [])) if telemetry else workflow.get("mcp_namespaces", []),
                "model_route_default_decision": route.get("default_decision") if route else None,
                "preferred_route_ids": route.get("preferred_route_ids", []) if route else [],
                "public_path": workflow.get("public_path"),
                "receipt_id": receipt.get("receipt_id") if receipt else None,
                "required_runtime_fields": profile.get("lineage_contract", {}).get("required_runtime_fields", []),
                "required_signal_classes": telemetry.get("required_signal_classes", []) if telemetry else [],
                "route_hash": route.get("workflow_route_hash") if route else None,
                "source_decision_counts": dict(sorted(source_decisions.items())),
                "source_hashes": {
                    source_id: source_by_id[source_id].get("source_hash")
                    for source_id in source_ids
                    if source_id in source_by_id
                },
                "source_ids": source_ids,
                "status": workflow.get("status"),
                "telemetry_decision": telemetry.get("decision") if telemetry else None,
                "title": workflow.get("title"),
                "workflow_id": workflow_id,
            }
        )
    return sorted(rows, key=lambda row: str(row["workflow_id"]))


def build_ledger(
    *,
    profile: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    refs: dict[str, Path],
    repo_root: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    source_rows = build_source_lineage(sources)
    workflow_rows = build_workflow_lineage(profile, sources, source_rows)
    source_decisions = Counter(str(row.get("decision")) for row in source_rows)
    workflow_decisions = Counter(str(row.get("decision")) for row in workflow_rows)
    reuse_counts = Counter(
        str(reuse_class)
        for row in workflow_rows
        for reuse_class in row.get("approved_reuse_classes", [])
    )

    return {
        "buyer_views": [
            {
                "id": "ai-platform-lineage-review",
                "question": "Can the platform prove which context entered each agent run and which controls governed the movement?",
                "uses": ["lineage_summary", "workflow_lineage", "source_lineage", "source_artifacts"],
            },
            {
                "id": "mcp-gateway-runtime-enforcement",
                "question": "Should an MCP gateway allow, hold, deny, or kill a context retrieval, route, handoff, egress, or reuse request?",
                "uses": ["lineage_contract", "workflow_lineage", "reuse_policy", "runtime_decision_examples"],
            },
            {
                "id": "acquisition-diligence-review",
                "question": "What evidence makes SecurityRecipes more valuable than a prompt library?",
                "uses": ["enterprise_adoption_packet", "commercialization_path", "workflow_lineage", "standards_alignment"],
            },
        ],
        "commercialization_path": profile.get("commercialization_path", {}),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "lineage_contract": profile.get("lineage_contract", {}),
        "lineage_stages": profile.get("lineage_stages", []),
        "lineage_summary": {
            "default_decision": profile.get("lineage_contract", {}).get("default_decision"),
            "failure_count": len(failures),
            "required_runtime_field_count": len(profile.get("lineage_contract", {}).get("required_runtime_fields", []) or []),
            "source_decision_counts": dict(sorted(source_decisions.items())),
            "source_lineage_count": len(source_rows),
            "stage_count": len(profile.get("lineage_stages", []) or []),
            "workflow_decision_counts": dict(sorted(workflow_decisions.items())),
            "workflow_lineage_count": len(workflow_rows),
            "workflow_reuse_class_counts": dict(sorted(reuse_counts.items())),
        },
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "The open ledger proves source-controlled reference lineage, not live customer runtime enforcement.",
                "treatment": "Bind hosted deployments to MCP gateway logs, model provider routing logs, identity issuance, egress decisions, handoff records, telemetry events, and signed receipt verification.",
            },
            {
                "risk": "Lineage can drift when a model route, MCP server, context source, source hash, workflow, or agent handoff changes.",
                "treatment": "Regenerate the ledger in CI and require runtime lineage checks before context crosses model, tenant, memory, tool, or handoff boundaries.",
            },
            {
                "risk": "A source can be valid but still contain documented adversarial examples that must be handled as evidence, not instructions.",
                "treatment": "Require runtime poisoning scan state, instruction demotion, citations, and gateway policy precedence for every retrieved context bundle.",
            },
        ],
        "reuse_policy": profile.get("reuse_policy", {}),
        "runtime_decision_examples": [
            {
                "id": "lineage-bound-vulnerable-dependency-run",
                "expect_decision": ALLOW_DECISION,
                "description": "A dependency remediation run presents matching source hashes, context package hash, clean runtime scan state, approved egress, telemetry, and receipt evidence.",
            },
            {
                "id": "cross-tenant-reuse-attempt",
                "expect_decision": "deny_cross_tenant_lineage_reuse",
                "description": "A tenant-bound context bundle is requested for a different tenant or public-corpus destination.",
            },
            {
                "id": "poisoned-context-runtime-break",
                "expect_decision": KILL_DECISION,
                "description": "A runtime poisoning scan reports hidden instructions, a secret exfiltration marker, or a context hash mismatch.",
            },
        ],
        "schema_version": SCHEMA_VERSION,
        "source_artifacts": source_artifacts(repo_root, refs, sources),
        "source_lineage": source_rows,
        "standards_alignment": profile.get("standards_alignment", []),
        "workflow_lineage": workflow_rows,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--context-trust-pack", type=Path, default=DEFAULT_CONTEXT_TRUST_PACK)
    parser.add_argument("--context-attestation-pack", type=Path, default=DEFAULT_CONTEXT_ATTESTATION_PACK)
    parser.add_argument("--context-poisoning-guard-pack", type=Path, default=DEFAULT_CONTEXT_POISONING_GUARD_PACK)
    parser.add_argument("--context-egress-boundary-pack", type=Path, default=DEFAULT_CONTEXT_EGRESS_BOUNDARY_PACK)
    parser.add_argument("--handoff-boundary-pack", type=Path, default=DEFAULT_HANDOFF_BOUNDARY_PACK)
    parser.add_argument("--telemetry-contract", type=Path, default=DEFAULT_TELEMETRY_CONTRACT)
    parser.add_argument("--run-receipt-pack", type=Path, default=DEFAULT_RUN_RECEIPT_PACK)
    parser.add_argument("--model-provider-routing-pack", type=Path, default=DEFAULT_MODEL_PROVIDER_ROUTING_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in lineage ledger is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    refs = {
        "secure_context_trust_pack": args.context_trust_pack,
        "secure_context_attestation_pack": args.context_attestation_pack,
        "context_poisoning_guard_pack": args.context_poisoning_guard_pack,
        "context_egress_boundary_pack": args.context_egress_boundary_pack,
        "agent_handoff_boundary_pack": args.handoff_boundary_pack,
        "agentic_telemetry_contract": args.telemetry_contract,
        "agentic_run_receipt_pack": args.run_receipt_pack,
        "model_provider_routing_pack": args.model_provider_routing_pack,
    }
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(resolve(repo_root, args.profile))
        sources = {key: load_json(resolve(repo_root, ref)) for key, ref in refs.items()}
        failures = [
            *validate_profile(profile),
            *validate_sources(sources),
        ]
        ledger = build_ledger(
            profile=profile,
            sources=sources,
            refs=refs,
            repo_root=repo_root,
            generated_at=args.generated_at,
            failures=failures,
        )
    except SecureContextLineageError as exc:
        print(f"secure context lineage ledger generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(ledger)
    if args.check:
        if failures:
            print("secure context lineage ledger validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_secure_context_lineage_ledger.py", file=sys.stderr)
            return 1
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_secure_context_lineage_ledger.py", file=sys.stderr)
            return 1
        print(f"Validated secure context lineage ledger: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")

    if failures:
        print("Generated secure context lineage ledger with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated secure context lineage ledger: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
