#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic run receipt pack.

The receipt pack answers the enterprise diligence question that sits
above every agentic workflow: what proof must exist before a run is
trusted? It joins the workflow manifest, MCP gateway policy, identity
ledger, secure context trust pack, context poisoning guard, context
egress boundary, readiness scorecard, red-team drills, system BOM, and
assurance pack into one machine-readable receipt template per workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any


PACK_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/agentic-run-receipt-profile.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_IDENTITY_LEDGER = Path("data/evidence/agent-identity-delegation-ledger.json")
DEFAULT_CONTEXT_TRUST_PACK = Path("data/evidence/secure-context-trust-pack.json")
DEFAULT_POISONING_GUARD_PACK = Path("data/evidence/context-poisoning-guard-pack.json")
DEFAULT_EGRESS_BOUNDARY_PACK = Path("data/evidence/context-egress-boundary-pack.json")
DEFAULT_READINESS_SCORECARD = Path("data/evidence/agentic-readiness-scorecard.json")
DEFAULT_RED_TEAM_PACK = Path("data/evidence/agentic-red-team-drill-pack.json")
DEFAULT_SYSTEM_BOM = Path("data/evidence/agentic-system-bom.json")
DEFAULT_ASSURANCE_PACK = Path("data/evidence/agentic-assurance-pack.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-run-receipt-pack.json")


REQUIRED_EVENT_CLASSES = {
    "identity_issued",
    "context_retrieval_decision",
    "context_poisoning_scan",
    "mcp_tool_decision",
    "context_egress_decision",
    "human_approval",
    "verifier_result",
    "evidence_attached",
    "run_closed",
    "identity_revoked",
}


class ReceiptGenerationError(RuntimeError):
    """Raised when the receipt pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReceiptGenerationError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ReceiptGenerationError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ReceiptGenerationError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReceiptGenerationError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReceiptGenerationError(f"{label} must be an object")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def normalize_path(path: Path) -> str:
    return path.as_posix()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def workflow_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    workflows = as_list(manifest.get("workflows"), "manifest.workflows")
    return {
        str(workflow.get("id")): workflow
        for workflow in workflows
        if isinstance(workflow, dict) and workflow.get("id")
    }


def policy_by_workflow_id(policy_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    policies = as_list(policy_pack.get("workflow_policies"), "policy_pack.workflow_policies")
    return {
        str(policy.get("workflow_id")): policy
        for policy in policies
        if isinstance(policy, dict) and policy.get("workflow_id")
    }


def identities_by_workflow(ledger: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = {}
    for identity in as_list(ledger.get("agent_identities"), "identity_ledger.agent_identities"):
        if not isinstance(identity, dict):
            continue
        workflow_id = str(identity.get("workflow_id", "")).strip()
        if workflow_id:
            output.setdefault(workflow_id, []).append(identity)
    for identities in output.values():
        identities.sort(key=lambda item: str(item.get("identity_id")))
    return output


def context_by_workflow(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = as_list(pack.get("workflow_context_map"), "secure_context_trust_pack.workflow_context_map")
    return {
        str(row.get("workflow_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("workflow_id")
    }


def egress_by_workflow(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = as_list(pack.get("workflow_egress_map"), "context_egress_boundary_pack.workflow_egress_map")
    return {
        str(row.get("workflow_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("workflow_id")
    }


def readiness_by_workflow(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = as_list(pack.get("workflow_readiness"), "readiness_scorecard.workflow_readiness")
    return {
        str(row.get("workflow_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("workflow_id")
    }


def red_team_by_workflow(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = as_list(pack.get("workflow_drills"), "red_team_drill_pack.workflow_drills")
    return {
        str(row.get("workflow_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("workflow_id")
    }


def assurance_by_workflow(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = as_list(pack.get("workflow_assurance"), "assurance_pack.workflow_assurance")
    return {
        str(row.get("workflow_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("workflow_id")
    }


def bom_workflows_by_id(system_bom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    components = as_dict(system_bom.get("components"), "system_bom.components")
    rows = as_list(components.get("workflows"), "system_bom.components.workflows")
    return {
        str(row.get("workflow_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("workflow_id")
    }


def source_failure_count(payloads: dict[str, dict[str, Any]]) -> int:
    count = 0
    for payload in payloads.values():
        failures = payload.get("failures", [])
        if isinstance(failures, list):
            count += len(failures)
    return count


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 80, failures, "profile intent must explain the product goal")
    standards = as_list(profile.get("standards_alignment"), "profile.standards_alignment")
    require(len(standards) >= 7, failures, "standards_alignment must include current AI and MCP references")
    for idx, standard in enumerate(standards):
        label = f"standards_alignment[{idx}]"
        if not isinstance(standard, dict):
            failures.append(f"{label} must be an object")
            continue
        require(str(standard.get("url", "")).startswith("https://"), failures, f"{label}.url must be https")
        require(len(str(standard.get("coverage", ""))) >= 50, failures, f"{label}.coverage must be specific")

    contract = as_dict(profile.get("receipt_contract"), "profile.receipt_contract")
    require(contract.get("default_state") == "untrusted_until_complete", failures, "receipt default_state must fail closed")
    runtime_attributes = as_list(contract.get("required_runtime_attributes"), "receipt_contract.required_runtime_attributes")
    require(len(runtime_attributes) >= 10, failures, "receipt runtime attributes must include identity, policy, context, and egress hashes")
    required_events = {str(event) for event in as_list(contract.get("required_event_classes"), "receipt_contract.required_event_classes")}
    missing = sorted(REQUIRED_EVENT_CLASSES - required_events)
    require(not missing, failures, f"receipt_contract is missing required events: {missing}")

    events = as_list(profile.get("event_classes"), "profile.event_classes")
    event_ids = {str(event.get("id")) for event in events if isinstance(event, dict)}
    require(REQUIRED_EVENT_CLASSES.issubset(event_ids), failures, "event_classes must define every required event")
    for event in events:
        if not isinstance(event, dict):
            failures.append("event_classes entries must be objects")
            continue
        event_id = str(event.get("id", "")).strip()
        fields = as_list(event.get("minimum_fields"), f"{event_id}.minimum_fields")
        require(len(fields) >= 5, failures, f"{event_id}: minimum_fields must include at least five fields")
        require(str(event.get("evidence_source", "")).strip(), failures, f"{event_id}: evidence_source is required")
        require(str(event.get("control_reason", "")).strip(), failures, f"{event_id}: control_reason is required")
    return failures


def validate_sources(
    *,
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    identity_ledger: dict[str, Any],
    context_trust_pack: dict[str, Any],
    egress_boundary_pack: dict[str, Any],
    readiness_scorecard: dict[str, Any],
    red_team_pack: dict[str, Any],
    assurance_pack: dict[str, Any],
    system_bom: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    require(manifest.get("schema_version") == "1.0", failures, "workflow manifest schema_version must be 1.0")
    require(policy_pack.get("schema_version") == "1.0", failures, "gateway policy schema_version must be 1.0")
    require(identity_ledger.get("schema_version") == "1.0", failures, "identity ledger schema_version must be 1.0")
    require(context_trust_pack.get("schema_version") == "1.0", failures, "secure context trust pack schema_version must be 1.0")
    require(egress_boundary_pack.get("schema_version") == "1.0", failures, "egress boundary pack schema_version must be 1.0")
    require(readiness_scorecard.get("schema_version") == "1.0", failures, "readiness scorecard schema_version must be 1.0")
    require(red_team_pack.get("schema_version") == "1.0", failures, "red-team drill pack schema_version must be 1.0")
    require(assurance_pack.get("schema_version") == "1.0", failures, "assurance pack schema_version must be 1.0")
    require(system_bom.get("schema_version") == "1.0", failures, "system BOM schema_version must be 1.0")

    workflows = set(workflow_by_id(manifest))
    require(bool(workflows), failures, "workflow manifest must include workflows")
    require(workflows == set(policy_by_workflow_id(policy_pack)), failures, "gateway policy workflows must match manifest")
    require(workflows == set(context_by_workflow(context_trust_pack)), failures, "secure context workflow map must match manifest")
    require(workflows == set(egress_by_workflow(egress_boundary_pack)), failures, "egress workflow map must match manifest")
    require(workflows == set(readiness_by_workflow(readiness_scorecard)), failures, "readiness workflow map must match manifest")
    require(workflows == set(red_team_by_workflow(red_team_pack)), failures, "red-team workflow map must match manifest")
    require(workflows == set(assurance_by_workflow(assurance_pack)), failures, "assurance workflow map must match manifest")
    require(workflows == set(bom_workflows_by_id(system_bom)), failures, "system BOM workflow map must match manifest")

    identity_workflows = set(identities_by_workflow(identity_ledger))
    require(workflows.issubset(identity_workflows), failures, "identity ledger must cover every workflow")

    return failures


def event_manifest(profile: dict[str, Any]) -> list[dict[str, Any]]:
    events = {
        str(event.get("id")): event
        for event in as_list(profile.get("event_classes"), "profile.event_classes")
        if isinstance(event, dict) and event.get("id")
    }
    required = [
        str(event_id)
        for event_id in as_dict(profile.get("receipt_contract"), "profile.receipt_contract").get(
            "required_event_classes",
            [],
        )
    ]
    return [
        {
            "control_reason": events[event_id].get("control_reason"),
            "event_class": event_id,
            "evidence_source": events[event_id].get("evidence_source"),
            "minimum_fields": events[event_id].get("minimum_fields", []),
            "required": True,
        }
        for event_id in required
        if event_id in events
    ]


def workflow_namespaces(workflow: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(context.get("namespace"))
            for context in workflow.get("mcp_context", []) or []
            if isinstance(context, dict) and context.get("namespace")
        }
    )


def required_human_approval_namespaces(identities: list[dict[str, Any]]) -> list[str]:
    namespaces = set()
    for identity in identities:
        authority = identity.get("delegated_authority", {})
        if isinstance(authority, dict):
            for namespace in authority.get("approval_required_namespaces", []) or []:
                namespaces.add(str(namespace))
    return sorted(namespaces)


def gateway_policy_hash(policy: dict[str, Any]) -> str:
    text = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_receipt_template(
    *,
    workflow: dict[str, Any],
    policy: dict[str, Any],
    identities: list[dict[str, Any]],
    context_row: dict[str, Any],
    egress_row: dict[str, Any],
    readiness_row: dict[str, Any],
    red_team_row: dict[str, Any],
    assurance_row: dict[str, Any],
    bom_row: dict[str, Any],
    events: list[dict[str, Any]],
    profile: dict[str, Any],
) -> dict[str, Any]:
    workflow_id = str(workflow.get("id"))
    evidence_records = workflow.get("evidence", [])
    if not isinstance(evidence_records, list):
        evidence_records = []
    namespaces = workflow_namespaces(workflow)
    identity_ids = [identity.get("identity_id") for identity in identities]
    approval_namespaces = required_human_approval_namespaces(identities)
    readiness_decision = readiness_row.get("decision")
    readiness_score = readiness_row.get("score")
    receipt_status = "receipt_ready" if readiness_decision == "scale_ready" else "receipt_required_for_guarded_pilot"

    return {
        "agent_classes": workflow.get("default_agents", []),
        "approval_required_namespaces": approval_namespaces,
        "assurance_control_ids": assurance_row.get("applicable_control_ids", []),
        "bom_component_id": bom_row.get("component_id"),
        "context_package_hash": context_row.get("context_package_hash"),
        "context_source_ids": context_row.get("source_ids", []),
        "egress_policy_hash": egress_row.get("egress_policy_hash"),
        "event_manifest": events,
        "expected_gateway_policy_hash": gateway_policy_hash(policy),
        "human_review_required": workflow.get("owner", {}).get("reviewer_pools") is not None,
        "identity_ids": identity_ids,
        "mcp_namespaces": namespaces,
        "minimum_evidence_records": [
            {
                "evidence_owner": record.get("evidence_owner"),
                "id": record.get("id"),
                "retention": record.get("retention"),
                "source": record.get("source"),
            }
            for record in evidence_records
            if isinstance(record, dict)
        ],
        "maturity_stage": workflow.get("maturity_stage"),
        "public_path": workflow.get("public_path"),
        "readiness_decision": readiness_decision,
        "readiness_score": readiness_score,
        "receipt_acceptance_criteria": profile.get("receipt_contract", {}).get("acceptance_criteria", []),
        "receipt_id": f"sr-run-receipt::{workflow_id}",
        "receipt_status": receipt_status,
        "red_team_drill_count": red_team_row.get("drill_count"),
        "required_event_class_count": len(events),
        "retention_days": profile.get("receipt_contract", {}).get("minimum_retention_days"),
        "runtime_attribute_contract": profile.get("receipt_contract", {}).get("required_runtime_attributes", []),
        "status": workflow.get("status"),
        "title": workflow.get("title"),
        "workflow_id": workflow_id,
    }


def build_pack(
    *,
    profile: dict[str, Any],
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    identity_ledger: dict[str, Any],
    context_trust_pack: dict[str, Any],
    poisoning_guard_pack: dict[str, Any],
    egress_boundary_pack: dict[str, Any],
    readiness_scorecard: dict[str, Any],
    red_team_pack: dict[str, Any],
    system_bom: dict[str, Any],
    assurance_pack: dict[str, Any],
    source_paths: dict[str, Path],
    source_refs: dict[str, Path],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    workflows = workflow_by_id(manifest)
    policies = policy_by_workflow_id(policy_pack)
    identities = identities_by_workflow(identity_ledger)
    context_rows = context_by_workflow(context_trust_pack)
    egress_rows = egress_by_workflow(egress_boundary_pack)
    readiness_rows = readiness_by_workflow(readiness_scorecard)
    red_team_rows = red_team_by_workflow(red_team_pack)
    assurance_rows = assurance_by_workflow(assurance_pack)
    bom_rows = bom_workflows_by_id(system_bom)
    events = event_manifest(profile)

    templates = [
        build_receipt_template(
            workflow=workflows[workflow_id],
            policy=policies.get(workflow_id, {}),
            identities=identities.get(workflow_id, []),
            context_row=context_rows.get(workflow_id, {}),
            egress_row=egress_rows.get(workflow_id, {}),
            readiness_row=readiness_rows.get(workflow_id, {}),
            red_team_row=red_team_rows.get(workflow_id, {}),
            assurance_row=assurance_rows.get(workflow_id, {}),
            bom_row=bom_rows.get(workflow_id, {}),
            events=events,
            profile=profile,
        )
        for workflow_id in sorted(workflows)
    ]

    decision_counts: dict[str, int] = {}
    for template in templates:
        decision = str(template.get("readiness_decision"))
        decision_counts[decision] = decision_counts.get(decision, 0) + 1

    source_artifacts = {
        artifact_id: {
            "path": normalize_path(source_refs[artifact_id]),
            "sha256": sha256_file(source_paths[artifact_id]),
        }
        for artifact_id in sorted(source_paths)
    }

    return {
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "example_receipt_envelope": {
            "receipt_id": "sr-run-receipt::<workflow_id>::<run_id>",
            "receipt_schema_version": PACK_SCHEMA_VERSION,
            "state": profile.get("receipt_contract", {}).get("default_state"),
            "runtime_attributes": profile.get("receipt_contract", {}).get("required_runtime_attributes", []),
            "events": [
                {
                    "event_class": event.get("event_class"),
                    "minimum_fields": event.get("minimum_fields"),
                }
                for event in events
            ],
            "signature": {
                "algorithm": profile.get("receipt_contract", {}).get("hash_algorithm"),
                "model": profile.get("receipt_contract", {}).get("signature_model"),
            },
        },
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "receipt_contract": profile.get("receipt_contract", {}),
        "receipt_pack_id": "security-recipes-agentic-run-receipts",
        "receipt_summary": {
            "default_state": profile.get("receipt_contract", {}).get("default_state"),
            "failure_count": len(failures),
            "readiness_decision_counts": dict(sorted(decision_counts.items())),
            "required_event_class_count": len(events),
            "source_failure_count": source_failure_count(
                {
                    "identity_ledger": identity_ledger,
                    "context_trust_pack": context_trust_pack,
                    "poisoning_guard_pack": poisoning_guard_pack,
                    "egress_boundary_pack": egress_boundary_pack,
                    "readiness_scorecard": readiness_scorecard,
                    "red_team_pack": red_team_pack,
                    "system_bom": system_bom,
                    "assurance_pack": assurance_pack,
                }
            ),
            "workflow_count": len(templates),
        },
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": source_artifacts,
        "standards_alignment": profile.get("standards_alignment", []),
        "workflow_receipt_templates": templates,
    }


def validate_pack(pack: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(pack.get("schema_version") == PACK_SCHEMA_VERSION, failures, "pack schema_version is invalid")
    summary = as_dict(pack.get("receipt_summary"), "receipt_summary")
    require(summary.get("default_state") == "untrusted_until_complete", failures, "receipt pack must fail closed")
    require(summary.get("source_failure_count") == 0, failures, "source packs must have zero failures")
    templates = as_list(pack.get("workflow_receipt_templates"), "workflow_receipt_templates")
    require(bool(templates), failures, "receipt pack must include workflow templates")
    for template in templates:
        if not isinstance(template, dict):
            failures.append("workflow receipt template must be an object")
            continue
        workflow_id = str(template.get("workflow_id", "")).strip()
        require(bool(template.get("identity_ids")), failures, f"{workflow_id}: identity_ids are required")
        require(bool(template.get("context_package_hash")), failures, f"{workflow_id}: context_package_hash is required")
        require(bool(template.get("egress_policy_hash")), failures, f"{workflow_id}: egress_policy_hash is required")
        require(len(template.get("event_manifest", [])) >= len(REQUIRED_EVENT_CLASSES), failures, f"{workflow_id}: event manifest is incomplete")
        require(len(template.get("minimum_evidence_records", [])) >= 3, failures, f"{workflow_id}: at least three evidence records are required")
    return failures


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--identity-ledger", type=Path, default=DEFAULT_IDENTITY_LEDGER)
    parser.add_argument("--context-trust-pack", type=Path, default=DEFAULT_CONTEXT_TRUST_PACK)
    parser.add_argument("--poisoning-guard-pack", type=Path, default=DEFAULT_POISONING_GUARD_PACK)
    parser.add_argument("--egress-boundary-pack", type=Path, default=DEFAULT_EGRESS_BOUNDARY_PACK)
    parser.add_argument("--readiness-scorecard", type=Path, default=DEFAULT_READINESS_SCORECARD)
    parser.add_argument("--red-team-pack", type=Path, default=DEFAULT_RED_TEAM_PACK)
    parser.add_argument("--system-bom", type=Path, default=DEFAULT_SYSTEM_BOM)
    parser.add_argument("--assurance-pack", type=Path, default=DEFAULT_ASSURANCE_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in receipt pack is stale.")
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
    paths = {
        "agentic_run_receipt_profile": resolve(repo_root, args.profile),
        "workflow_manifest": resolve(repo_root, args.manifest),
        "mcp_gateway_policy": resolve(repo_root, args.policy),
        "agent_identity_ledger": resolve(repo_root, args.identity_ledger),
        "secure_context_trust_pack": resolve(repo_root, args.context_trust_pack),
        "context_poisoning_guard_pack": resolve(repo_root, args.poisoning_guard_pack),
        "context_egress_boundary_pack": resolve(repo_root, args.egress_boundary_pack),
        "agentic_readiness_scorecard": resolve(repo_root, args.readiness_scorecard),
        "agentic_red_team_drill_pack": resolve(repo_root, args.red_team_pack),
        "agentic_system_bom": resolve(repo_root, args.system_bom),
        "agentic_assurance_pack": resolve(repo_root, args.assurance_pack),
    }
    refs = {
        "agentic_run_receipt_profile": args.profile,
        "workflow_manifest": args.manifest,
        "mcp_gateway_policy": args.policy,
        "agent_identity_ledger": args.identity_ledger,
        "secure_context_trust_pack": args.context_trust_pack,
        "context_poisoning_guard_pack": args.poisoning_guard_pack,
        "context_egress_boundary_pack": args.egress_boundary_pack,
        "agentic_readiness_scorecard": args.readiness_scorecard,
        "agentic_red_team_drill_pack": args.red_team_pack,
        "agentic_system_bom": args.system_bom,
        "agentic_assurance_pack": args.assurance_pack,
    }
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(paths["agentic_run_receipt_profile"])
        manifest = load_json(paths["workflow_manifest"])
        policy_pack = load_json(paths["mcp_gateway_policy"])
        identity_ledger = load_json(paths["agent_identity_ledger"])
        context_trust_pack = load_json(paths["secure_context_trust_pack"])
        poisoning_guard_pack = load_json(paths["context_poisoning_guard_pack"])
        egress_boundary_pack = load_json(paths["context_egress_boundary_pack"])
        readiness_scorecard = load_json(paths["agentic_readiness_scorecard"])
        red_team_pack = load_json(paths["agentic_red_team_drill_pack"])
        system_bom = load_json(paths["agentic_system_bom"])
        assurance_pack = load_json(paths["agentic_assurance_pack"])
        failures = validate_profile(profile)
        failures.extend(
            validate_sources(
                manifest=manifest,
                policy_pack=policy_pack,
                identity_ledger=identity_ledger,
                context_trust_pack=context_trust_pack,
                egress_boundary_pack=egress_boundary_pack,
                readiness_scorecard=readiness_scorecard,
                red_team_pack=red_team_pack,
                assurance_pack=assurance_pack,
                system_bom=system_bom,
            )
        )
        pack = build_pack(
            profile=profile,
            manifest=manifest,
            policy_pack=policy_pack,
            identity_ledger=identity_ledger,
            context_trust_pack=context_trust_pack,
            poisoning_guard_pack=poisoning_guard_pack,
            egress_boundary_pack=egress_boundary_pack,
            readiness_scorecard=readiness_scorecard,
            red_team_pack=red_team_pack,
            system_bom=system_bom,
            assurance_pack=assurance_pack,
            source_paths=paths,
            source_refs=refs,
            generated_at=args.generated_at,
            failures=failures,
        )
        pack["failures"].extend(validate_pack(pack))
    except ReceiptGenerationError as exc:
        print(f"agentic run receipt pack generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)

    if args.check:
        if pack.get("failures"):
            print("agentic run receipt pack validation failed:", file=sys.stderr)
            for failure in pack["failures"]:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            if should_update_stale_output(args):
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(next_text, encoding="utf-8")
                print(f"Generated missing agentic run receipt pack: {output_path}")
                return 0
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            if should_update_stale_output(args):
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(next_text, encoding="utf-8")
                print(f"Refreshed stale agentic run receipt pack: {output_path}")
                return 0
            print(f"{output_path} is stale; run scripts/generate_agentic_run_receipt_pack.py", file=sys.stderr)
            return 1
        print(f"Validated agentic run receipt pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if pack.get("failures"):
        print("Generated agentic run receipt pack with validation failures:", file=sys.stderr)
        for failure in pack["failures"]:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agentic run receipt pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
