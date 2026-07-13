#!/usr/bin/env python3
"""Generate the SecurityRecipes agent memory boundary pack.

The secure context layer should govern not only what agents retrieve,
but also what they remember. Persistent memory, vector indexes, project
state, user preferences, run receipts, and tool-result summaries can
turn one bad context event into a cross-run compromise. This generator
joins the memory boundary model with workflow manifests and emits a
machine-readable pack for MCP tools, platform intake, and audit review.
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


DEFAULT_MODEL = Path("data/assurance/agent-memory-boundary-model.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_OUTPUT = Path("data/evidence/agent-memory-boundary-pack.json")

PACK_SCHEMA_VERSION = "1.0"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")
VALID_DECISIONS = {
    "allow_ephemeral_memory",
    "allow_append_only_evidence_memory",
    "allow_readonly_policy_memory",
    "hold_for_tenant_memory_boundary",
    "hold_for_memory_admission_review",
    "deny_runtime_memory_write",
    "deny_cross_tenant_memory",
    "kill_session_on_prohibited_memory",
}
ALLOW_DECISIONS = {
    "allow_ephemeral_memory",
    "allow_append_only_evidence_memory",
    "allow_readonly_policy_memory",
}
HOLD_DECISIONS = {
    "hold_for_tenant_memory_boundary",
    "hold_for_memory_admission_review",
}


class AgentMemoryBoundaryError(RuntimeError):
    """Raised when the agent memory boundary pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AgentMemoryBoundaryError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AgentMemoryBoundaryError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AgentMemoryBoundaryError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AgentMemoryBoundaryError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentMemoryBoundaryError(f"{label} must be an object")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def stable_hash(payload: Any) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def validate_model(model: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(model.get("schema_version") == "1.0", failures, "model schema_version must be 1.0")
    require(len(str(model.get("intent", ""))) >= 80, failures, "model intent must explain the product goal")

    standards = as_list(model.get("standards_alignment"), "standards_alignment")
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

    contract = as_dict(model.get("memory_decision_contract"), "memory_decision_contract")
    require(
        contract.get("default_decision") == "hold_for_memory_admission_review",
        failures,
        "default memory decision must be hold_for_memory_admission_review",
    )
    require(len(as_list(contract.get("runtime_attributes"), "memory_decision_contract.runtime_attributes")) >= 10, failures, "memory decision contract must declare runtime attributes")
    require(len(as_list(contract.get("global_rules"), "memory_decision_contract.global_rules")) >= 5, failures, "memory decision contract must include global rules")
    require(len(as_list(contract.get("prohibited_data_classes"), "memory_decision_contract.prohibited_data_classes")) >= 5, failures, "memory decision contract must list prohibited data classes")

    required_classes = {
        "ephemeral-scratchpad",
        "run-receipt-evidence",
        "workflow-policy-memory",
        "customer-runtime-memory",
        "vector-embedding-memory",
        "prohibited-memory",
    }
    classes = as_list(model.get("memory_classes"), "memory_classes")
    require(len(classes) >= len(required_classes), failures, "memory_classes must include required classes")
    seen_classes: set[str] = set()
    allowed_operations = {"read", "write", "delete", "reindex", "replay", "export"}
    covered_risks: set[str] = set()

    for idx, memory_class in enumerate(classes):
        label = f"memory_classes[{idx}]"
        if not isinstance(memory_class, dict):
            failures.append(f"{label} must be an object")
            continue
        class_id = str(memory_class.get("id", "")).strip()
        decision = str(memory_class.get("default_decision", "")).strip()
        operations = {str(item) for item in as_list(memory_class.get("allowed_operations"), f"{label}.allowed_operations")}
        controls = {str(item) for item in as_list(memory_class.get("required_controls"), f"{label}.required_controls")}
        risks = {str(item) for item in as_list(memory_class.get("risk_families"), f"{label}.risk_families")}

        require(bool(ID_RE.match(class_id)), failures, f"{label}.id must be kebab-case")
        require(class_id not in seen_classes, failures, f"{label}.id duplicates {class_id}")
        seen_classes.add(class_id)
        require(decision in VALID_DECISIONS, failures, f"{class_id}: default_decision is unknown: {decision}")
        require(operations.issubset(allowed_operations), failures, f"{class_id}: allowed_operations include unsupported values")
        require(bool(str(memory_class.get("title", "")).strip()), failures, f"{class_id}: title is required")
        require(bool(str(memory_class.get("kind", "")).strip()), failures, f"{class_id}: kind is required")
        require(isinstance(memory_class.get("persistent"), bool), failures, f"{class_id}: persistent must be boolean")
        require(isinstance(memory_class.get("runtime_writes_allowed"), bool), failures, f"{class_id}: runtime_writes_allowed must be boolean")
        require(int(memory_class.get("max_ttl_days") or 0) >= int(memory_class.get("ttl_days") or 0), failures, f"{class_id}: max_ttl_days must be >= ttl_days")
        require(bool(controls), failures, f"{class_id}: required_controls are required")
        require(bool(as_list(memory_class.get("evidence_required"), f"{label}.evidence_required")), failures, f"{class_id}: evidence_required is required")
        require(bool(as_list(memory_class.get("write_controls"), f"{label}.write_controls")), failures, f"{class_id}: write_controls are required")
        require(bool(risks), failures, f"{class_id}: risk_families are required")
        covered_risks.update(risks)

        if memory_class.get("persistent"):
            require("provenance_hash" in controls or bool(memory_class.get("provenance_hash_required")), failures, f"{class_id}: persistent memory must require provenance")
        if memory_class.get("tenant_id_required"):
            require("tenant_bound" in controls or "tenant_isolated" in controls, failures, f"{class_id}: tenant memory must declare tenant controls")
        if decision in ALLOW_DECISIONS:
            require("kill_session_on_prohibited_memory" != decision, failures, f"{class_id}: allow class cannot be prohibited")
        if decision == "kill_session_on_prohibited_memory":
            require(not operations, failures, f"{class_id}: prohibited memory must not allow operations")

    missing_classes = sorted(required_classes - seen_classes)
    require(not missing_classes, failures, f"memory_classes missing required classes: {missing_classes}")
    require("memory_poisoning" in covered_risks, failures, "memory_classes must cover memory_poisoning")
    require("secret_exposure" in covered_risks, failures, "memory_classes must cover secret_exposure")

    defaults = as_dict(model.get("workflow_memory_defaults"), "workflow_memory_defaults")
    default_class_ids = {str(item) for item in as_list(defaults.get("default_memory_class_ids"), "workflow_memory_defaults.default_memory_class_ids")}
    missing_defaults = sorted(default_class_ids - seen_classes)
    require(not missing_defaults, failures, f"default memory classes are not registered: {missing_defaults}")
    require(len(as_list(defaults.get("required_profile_controls"), "workflow_memory_defaults.required_profile_controls")) >= 5, failures, "workflow_memory_defaults.required_profile_controls must be specific")

    return failures


def validate_manifest(manifest: dict[str, Any], model: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    workflows = as_list(manifest.get("workflows"), "manifest.workflows")
    minimum_evidence = int(model.get("workflow_memory_defaults", {}).get("minimum_evidence_records_per_workflow", 3))
    require(bool(workflows), failures, "workflow manifest must include workflows")
    for idx, workflow in enumerate(workflows):
        label = f"manifest.workflows[{idx}]"
        if not isinstance(workflow, dict):
            failures.append(f"{label} must be an object")
            continue
        workflow_id = str(workflow.get("id", "")).strip()
        require(bool(ID_RE.match(workflow_id)), failures, f"{label}.id must be kebab-case")
        require(bool(workflow.get("mcp_context")), failures, f"{workflow_id}: mcp_context is required")
        require(len(workflow.get("evidence", []) or []) >= minimum_evidence, failures, f"{workflow_id}: insufficient evidence records for memory profile")
        require(bool(workflow.get("kill_signals")), failures, f"{workflow_id}: kill_signals are required for memory profile")
    return failures


def memory_classes_by_id(model: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(memory_class.get("id")): memory_class
        for memory_class in model.get("memory_classes", [])
        if isinstance(memory_class, dict) and memory_class.get("id")
    }


def memory_class_preview(memory_class: dict[str, Any]) -> dict[str, Any]:
    return {
        "allowed_data_classes": memory_class.get("allowed_data_classes", []),
        "allowed_operations": memory_class.get("allowed_operations", []),
        "append_only": memory_class.get("append_only"),
        "default_decision": memory_class.get("default_decision"),
        "denied_data_classes": memory_class.get("denied_data_classes", []),
        "evidence_required": memory_class.get("evidence_required", []),
        "exposure": memory_class.get("exposure"),
        "human_approval_required": memory_class.get("human_approval_required"),
        "id": memory_class.get("id"),
        "kind": memory_class.get("kind"),
        "max_ttl_days": memory_class.get("max_ttl_days"),
        "persistent": memory_class.get("persistent"),
        "provenance_hash_required": memory_class.get("provenance_hash_required"),
        "required_controls": memory_class.get("required_controls", []),
        "risk_families": memory_class.get("risk_families", []),
        "rollback_required": memory_class.get("rollback_required"),
        "runtime_writes_allowed": memory_class.get("runtime_writes_allowed"),
        "tenant_id_required": memory_class.get("tenant_id_required"),
        "title": memory_class.get("title"),
        "trust_tier": memory_class.get("trust_tier"),
        "ttl_days": memory_class.get("ttl_days"),
        "write_controls": memory_class.get("write_controls", []),
    }


def workflow_profile_hash(workflow: dict[str, Any], class_rows: list[dict[str, Any]]) -> str:
    payload = {
        "agent_classes": workflow.get("default_agents", []),
        "memory_classes": [
            {
                "default_decision": row.get("default_decision"),
                "id": row.get("id"),
                "max_ttl_days": row.get("max_ttl_days"),
                "required_controls": row.get("required_controls", []),
            }
            for row in class_rows
        ],
        "mcp_context": workflow.get("mcp_context", []),
        "workflow_id": workflow.get("id"),
    }
    return stable_hash(payload)


def build_workflow_profiles(model: dict[str, Any], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    classes = memory_classes_by_id(model)
    default_class_ids = [
        str(class_id)
        for class_id in model.get("workflow_memory_defaults", {}).get("default_memory_class_ids", [])
    ]
    class_rows = [
        memory_class_preview(classes[class_id])
        for class_id in default_class_ids
        if class_id in classes
    ]
    rows: list[dict[str, Any]] = []
    for workflow in manifest.get("workflows", []):
        if not isinstance(workflow, dict):
            continue
        workflow_id = str(workflow.get("id"))
        allowed = [
            row.get("id")
            for row in class_rows
            if row.get("default_decision") in ALLOW_DECISIONS
        ]
        hold = [
            row.get("id")
            for row in class_rows
            if row.get("default_decision") in HOLD_DECISIONS
        ]
        kill = [
            row.get("id")
            for row in class_rows
            if row.get("default_decision") == "kill_session_on_prohibited_memory"
        ]
        namespace_rows = [
            {
                "access": context.get("access"),
                "memory_boundary": "tenant_bound" if context.get("access") in {"write_branch", "write_ticket", "approval_required"} else "read_only_or_ephemeral",
                "namespace": context.get("namespace"),
                "purpose": context.get("purpose"),
            }
            for context in workflow.get("mcp_context", [])
            if isinstance(context, dict)
        ]
        rows.append(
            {
                "agent_classes": workflow.get("default_agents", []),
                "allowed_memory_class_ids": allowed,
                "control_profile": {
                    "manual_review_required_for": model.get("workflow_memory_defaults", {}).get("manual_review_required_for", []),
                    "required_profile_controls": model.get("workflow_memory_defaults", {}).get("required_profile_controls", []),
                },
                "default_memory_class_ids": default_class_ids,
                "evidence_records": [
                    {
                        "id": evidence.get("id"),
                        "owner": evidence.get("evidence_owner"),
                        "retention": evidence.get("retention"),
                        "source": evidence.get("source"),
                    }
                    for evidence in workflow.get("evidence", [])
                    if isinstance(evidence, dict)
                ],
                "hold_memory_class_ids": hold,
                "kill_memory_class_ids": kill,
                "kill_signal_count": len(workflow.get("kill_signals", []) or []),
                "maturity_stage": workflow.get("maturity_stage"),
                "memory_boundary_summary": "Ephemeral scratchpad is allowed; policy memory is read-only; run receipts are append-only; customer, preference, and vector memory hold for tenant controls; prohibited memory kills the session.",
                "memory_profile_hash": workflow_profile_hash(workflow, class_rows),
                "namespace_memory_boundaries": namespace_rows,
                "public_path": workflow.get("public_path"),
                "status": workflow.get("status"),
                "title": workflow.get("title"),
                "workflow_id": workflow_id,
            }
        )
    return rows


def build_pack(
    *,
    model: dict[str, Any],
    manifest: dict[str, Any],
    model_path: Path,
    manifest_path: Path,
    model_ref: Path,
    manifest_ref: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    memory_classes = [memory_class_preview(row) for row in model.get("memory_classes", []) if isinstance(row, dict)]
    workflow_profiles = build_workflow_profiles(model, manifest)
    decision_counts = Counter(str(row.get("default_decision")) for row in memory_classes)
    risk_counts = Counter(
        str(risk)
        for row in memory_classes
        for risk in row.get("risk_families", [])
    )
    kind_counts = Counter(str(row.get("kind")) for row in memory_classes)

    return {
        "agent_memory_boundary_summary": {
            "allow_class_count": sum(1 for row in memory_classes if row.get("default_decision") in ALLOW_DECISIONS),
            "decision_counts": dict(sorted(decision_counts.items())),
            "failure_count": len(failures),
            "hold_class_count": sum(1 for row in memory_classes if row.get("default_decision") in HOLD_DECISIONS),
            "kill_class_count": sum(1 for row in memory_classes if row.get("default_decision") == "kill_session_on_prohibited_memory"),
            "memory_class_count": len(memory_classes),
            "memory_kind_counts": dict(sorted(kind_counts.items())),
            "persistent_class_count": sum(1 for row in memory_classes if row.get("persistent")),
            "prohibited_data_class_count": len(model.get("memory_decision_contract", {}).get("prohibited_data_classes", []) or []),
            "risk_family_counts": dict(sorted(risk_counts.items())),
            "workflow_profile_count": len(workflow_profiles),
        },
        "enterprise_adoption_packet": model.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(model.get("last_reviewed", "")),
        "intent": model.get("intent"),
        "memory_classes": memory_classes,
        "memory_decision_contract": model.get("memory_decision_contract", {}),
        "positioning": model.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "Memory controls do not prove every downstream agent framework enforces them.",
                "treatment": "Deploying organizations must bind the pack to an MCP gateway, memory middleware, or agent host that can enforce read, write, delete, and replay decisions."
            },
            {
                "risk": "Cryptographic hashes prove memory provenance, not semantic truth.",
                "treatment": "Persistent memories still require poisoning scans, source recertification, verifier evidence, and rollback paths."
            },
            {
                "risk": "Tenant-specific memory policy is customer-specific.",
                "treatment": "Customer memory stores must supply tenant IDs, retention, DLP, approval, and deletion evidence before persistence is allowed."
            }
        ],
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": {
            "agent_memory_boundary_model": {
                "path": normalize_path(model_ref),
                "sha256": sha256_file(model_path),
            },
            "workflow_manifest": {
                "path": normalize_path(manifest_ref),
                "sha256": sha256_file(manifest_path),
            },
        },
        "standards_alignment": model.get("standards_alignment", []),
        "workflow_memory_defaults": model.get("workflow_memory_defaults", {}),
        "workflow_memory_profiles": workflow_profiles,
    }


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in agent memory boundary pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    model_path = resolve(repo_root, args.model)
    manifest_path = resolve(repo_root, args.manifest)
    output_path = resolve(repo_root, args.output)

    try:
        model = load_json(model_path)
        manifest = load_json(manifest_path)
        failures = validate_model(model)
        failures.extend(validate_manifest(manifest, model))
        pack = build_pack(
            model=model,
            manifest=manifest,
            model_path=model_path,
            manifest_path=manifest_path,
            model_ref=args.model,
            manifest_ref=args.manifest,
            generated_at=args.generated_at,
            failures=failures,
        )
    except AgentMemoryBoundaryError as exc:
        print(f"agent memory boundary pack generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)

    if args.check:
        if failures:
            print("agent memory boundary pack validation failed:", file=sys.stderr)
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
                f"{output_path} is stale; run scripts/generate_agent_memory_boundary_pack.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated agent memory boundary pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated agent memory boundary pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agent memory boundary pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
