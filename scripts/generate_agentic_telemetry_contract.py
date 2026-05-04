#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic telemetry contract.

The telemetry contract turns the secure context layer into an
observability control: agent, model, MCP, context, policy, egress,
approval, verifier, and incident events are trusted only when they carry
the minimum trace fields needed for reconstruction and avoid raw secret
or sensitive payload capture by default.
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
DEFAULT_PROFILE = Path("data/assurance/agentic-telemetry-contract-profile.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_MEASUREMENT_PROBE_PACK = Path("data/evidence/agentic-measurement-probe-pack.json")
DEFAULT_RUN_RECEIPT_PACK = Path("data/evidence/agentic-run-receipt-pack.json")
DEFAULT_EGRESS_BOUNDARY_PACK = Path("data/evidence/context-egress-boundary-pack.json")
DEFAULT_INCIDENT_RESPONSE_PACK = Path("data/evidence/agentic-incident-response-pack.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-telemetry-contract.json")

REQUIRED_SIGNAL_CLASSES = {
    "agent_session",
    "model_call",
    "mcp_tool_call",
    "context_retrieval",
    "policy_decision",
    "egress_decision",
    "human_approval",
    "verifier_result",
    "incident_signal",
}
REQUIRED_TRACE_ATTRIBUTES = {
    "service.name",
    "deployment.environment",
    "trace_id",
    "span_id",
    "workflow_id",
    "run_id",
    "agent_id",
    "identity_id",
    "correlation_id",
    "gen_ai.operation.name",
    "mcp.session.id",
    "mcp.method.name",
    "policy.decision",
    "policy.pack_hash",
    "context.package_hash",
    "egress.decision",
    "receipt_id",
    "telemetry.redaction_state",
}


class TelemetryContractError(RuntimeError):
    """Raised when the telemetry contract cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TelemetryContractError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise TelemetryContractError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise TelemetryContractError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TelemetryContractError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise TelemetryContractError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def rows_by_id(rows: list[Any], key: str) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and row.get(key):
            output[str(row.get(key))] = row
    return output


def workflow_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return rows_by_id(as_list(manifest.get("workflows"), "workflow_manifest.workflows"), "id")


def workflow_rows(pack: dict[str, Any], field: str, key: str = "workflow_id") -> dict[str, dict[str, Any]]:
    return rows_by_id(as_list(pack.get(field), field), key)


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 100, failures, "profile intent must explain the telemetry product goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 8, failures, "standards_alignment must include current AI, MCP, telemetry, and data-security references")
    seen_standards: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in seen_standards, failures, f"{standard_id}: duplicate standard id")
        seen_standards.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 50, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("telemetry_contract"), "telemetry_contract")
    require(
        contract.get("default_state") == "untrusted_until_required_trace_fields_present",
        failures,
        "telemetry contract default_state must fail closed",
    )
    required_classes = {str(item) for item in as_list(contract.get("required_signal_classes"), "required_signal_classes")}
    require(REQUIRED_SIGNAL_CLASSES.issubset(required_classes), failures, "telemetry contract is missing required signal classes")
    required_attributes = {str(item) for item in as_list(contract.get("required_trace_attributes"), "required_trace_attributes")}
    require(REQUIRED_TRACE_ATTRIBUTES.issubset(required_attributes), failures, "telemetry contract is missing required trace attributes")
    require(bool(contract.get("redaction_required_by_default")), failures, "telemetry must require redaction by default")

    signal_classes = as_list(profile.get("signal_classes"), "signal_classes")
    class_ids: set[str] = set()
    for idx, signal_class in enumerate(signal_classes):
        item = as_dict(signal_class, f"signal_classes[{idx}]")
        class_id = str(item.get("id", "")).strip()
        class_ids.add(class_id)
        require(class_id in REQUIRED_SIGNAL_CLASSES, failures, f"unknown signal class: {class_id}")
        require(str(item.get("event_class", "")).strip(), failures, f"{class_id}: event_class is required")
        require(len(as_list(item.get("required_attributes"), f"{class_id}.required_attributes")) >= 5, failures, f"{class_id}: required_attributes must be specific")
        require(len(str(item.get("minimum_evidence", ""))) >= 70, failures, f"{class_id}: minimum_evidence must be specific")
    require(REQUIRED_SIGNAL_CLASSES.issubset(class_ids), failures, "signal_classes must define every required class")

    tiers = rows_by_id(as_list(profile.get("redaction_tiers"), "redaction_tiers"), "id")
    require({"public_metadata", "internal_metadata", "sensitive_content", "prohibited_secret"}.issubset(tiers), failures, "redaction tiers are incomplete")
    checks = as_list(profile.get("telemetry_checks"), "telemetry_checks")
    require(len(checks) >= 7, failures, "telemetry_checks must include core reconstruction and redaction checks")
    for idx, check in enumerate(checks):
        item = as_dict(check, f"telemetry_checks[{idx}]")
        check_id = str(item.get("id", "")).strip()
        require(bool(check_id), failures, f"telemetry_checks[{idx}].id is required")
        require(str(item.get("class_id")) in class_ids, failures, f"{check_id}: class_id is unknown")
        require(bool(as_list(item.get("required_attributes"), f"{check_id}.required_attributes")), failures, f"{check_id}: required_attributes are required")
        require(len(as_list(item.get("pass_conditions"), f"{check_id}.pass_conditions")) >= 3, failures, f"{check_id}: pass_conditions must include at least three items")
    return failures


def source_failure_count(payloads: dict[str, dict[str, Any]]) -> int:
    count = 0
    for payload in payloads.values():
        failures = payload.get("failures")
        if isinstance(failures, list):
            count += len(failures)
    return count


def validate_sources(source_payloads: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    manifest = source_payloads["workflow_manifest"]
    measurement = source_payloads["agentic_measurement_probe_pack"]
    receipts = source_payloads["agentic_run_receipt_pack"]
    egress = source_payloads["context_egress_boundary_pack"]
    incident = source_payloads["agentic_incident_response_pack"]

    for label, payload in source_payloads.items():
        require(payload.get("schema_version") == "1.0", failures, f"{label} schema_version must be 1.0")
    require(source_failure_count(source_payloads) == 0, failures, "source packs must have zero validation failures")

    workflow_ids = set(workflow_by_id(manifest))
    require(bool(workflow_ids), failures, "workflow manifest must include workflows")
    require(workflow_ids == set(workflow_rows(measurement, "workflow_probes")), failures, "measurement workflows must match manifest")
    require(workflow_ids == set(workflow_rows(receipts, "workflow_receipt_templates")), failures, "run receipt workflows must match manifest")
    require(workflow_ids == set(workflow_rows(egress, "workflow_egress_map")), failures, "egress workflows must match manifest")
    require(workflow_ids == set(workflow_rows(incident, "workflow_response_matrix")), failures, "incident workflows must match manifest")
    return failures


def workflow_namespaces(workflow: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(context.get("namespace"))
            for context in workflow.get("mcp_context", []) or []
            if isinstance(context, dict) and context.get("namespace")
        }
    )


def signal_attributes(profile: dict[str, Any], signal_class_id: str) -> list[str]:
    for signal_class in profile.get("signal_classes", []):
        if isinstance(signal_class, dict) and signal_class.get("id") == signal_class_id:
            return [str(item) for item in signal_class.get("required_attributes", [])]
    return []


def build_workflow_contract(
    *,
    workflow: dict[str, Any],
    profile: dict[str, Any],
    measurement_row: dict[str, Any],
    receipt_row: dict[str, Any],
    egress_row: dict[str, Any],
    incident_row: dict[str, Any],
) -> dict[str, Any]:
    workflow_id = str(workflow.get("id"))
    contract = profile.get("telemetry_contract", {})
    required_classes = [str(item) for item in contract.get("required_signal_classes", [])]
    required_attributes = sorted(
        {
            *[str(item) for item in contract.get("required_trace_attributes", [])],
            *[
                attr
                for class_id in required_classes
                for attr in signal_attributes(profile, class_id)
            ],
        }
    )
    score = int(measurement_row.get("score") or 0)
    source_ready = bool(receipt_row) and bool(egress_row) and bool(incident_row)
    decision = "telemetry_ready" if source_ready and score >= 85 else "hold_for_trace_completion"
    return {
        "agent_classes": workflow.get("default_agents", []),
        "context_package_hash": receipt_row.get("context_package_hash"),
        "decision": decision,
        "egress_policy_hash": egress_row.get("egress_policy_hash"),
        "incident_default_decision": incident_row.get("default_response_decision"),
        "maturity_stage": workflow.get("maturity_stage"),
        "mcp_namespaces": workflow_namespaces(workflow),
        "measurement_decision": measurement_row.get("decision"),
        "measurement_score": score,
        "minimum_retention_days": contract.get("minimum_retention_days"),
        "public_path": workflow.get("public_path"),
        "receipt_id": receipt_row.get("receipt_id"),
        "redaction_required_by_default": contract.get("redaction_required_by_default"),
        "required_attributes": required_attributes,
        "required_signal_classes": required_classes,
        "status": workflow.get("status"),
        "title": workflow.get("title"),
        "workflow_id": workflow_id,
    }


def build_source_artifacts(repo_root: Path, refs: dict[str, Path]) -> dict[str, dict[str, str]]:
    output: dict[str, dict[str, str]] = {}
    for key, ref in sorted(refs.items()):
        path = resolve(repo_root, ref)
        output[key] = {
            "path": normalize_path(ref),
            "sha256": sha256_file(path),
        }
    return output


def build_summary(workflows: list[dict[str, Any]], profile: dict[str, Any], failures: list[str]) -> dict[str, Any]:
    decisions = Counter(str(row.get("decision")) for row in workflows)
    return {
        "default_state": profile.get("telemetry_contract", {}).get("default_state"),
        "decision_counts": dict(sorted(decisions.items())),
        "failure_count": len(failures),
        "prohibited_field_count": len(profile.get("telemetry_contract", {}).get("prohibited_telemetry_fields", [])),
        "redaction_tier_count": len(profile.get("redaction_tiers", [])),
        "required_attribute_count": len(profile.get("telemetry_contract", {}).get("required_trace_attributes", [])),
        "sensitive_opt_in_attribute_count": len(profile.get("telemetry_contract", {}).get("sensitive_opt_in_attributes", [])),
        "signal_class_count": len(profile.get("signal_classes", [])),
        "telemetry_check_count": len(profile.get("telemetry_checks", [])),
        "workflow_count": len(workflows),
    }


def build_pack(
    *,
    profile: dict[str, Any],
    source_payloads: dict[str, dict[str, Any]],
    source_artifacts: dict[str, dict[str, str]],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    workflows = workflow_by_id(source_payloads["workflow_manifest"])
    measurement = workflow_rows(source_payloads["agentic_measurement_probe_pack"], "workflow_probes")
    receipts = workflow_rows(source_payloads["agentic_run_receipt_pack"], "workflow_receipt_templates")
    egress = workflow_rows(source_payloads["context_egress_boundary_pack"], "workflow_egress_map")
    incidents = workflow_rows(source_payloads["agentic_incident_response_pack"], "workflow_response_matrix")
    workflow_contracts = [
        build_workflow_contract(
            workflow=workflows[workflow_id],
            profile=profile,
            measurement_row=measurement.get(workflow_id, {}),
            receipt_row=receipts.get(workflow_id, {}),
            egress_row=egress.get(workflow_id, {}),
            incident_row=incidents.get(workflow_id, {}),
        )
        for workflow_id in sorted(workflows)
    ]
    return {
        "commercialization_path": profile.get("commercialization_path", {}),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "evaluator_contract": {
            "default_decision_for_missing_fields": "hold_for_trace_completion",
            "decision_order": [
                "kill_session_on_secret_telemetry",
                "deny_raw_sensitive_telemetry",
                "hold_for_unregistered_workflow",
                "hold_for_trace_completion",
                "telemetry_ready"
            ],
            "required_attribute_source": "telemetry_contract.required_trace_attributes plus signal class required_attributes",
        },
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "redaction_tiers": profile.get("redaction_tiers", []),
        "residual_risks": [
            {
                "risk": "This open contract verifies expected telemetry shape, not a customer's live collector configuration.",
                "treatment": "Bind the same contract to tenant-specific OpenTelemetry collectors, SIEM pipelines, and MCP gateway logs."
            },
            {
                "risk": "Sensitive prompt or tool payload capture can be useful during debugging but dangerous in production.",
                "treatment": "Require explicit opt-in, redaction verification, access controls, and retention limits before collecting sensitive content attributes."
            },
            {
                "risk": "OpenTelemetry GenAI and MCP conventions are still evolving.",
                "treatment": "Version the contract and re-run compatibility checks after semantic-convention or MCP specification changes."
            }
        ],
        "schema_version": PACK_SCHEMA_VERSION,
        "selected_feature": {
            "id": "agentic-telemetry-contract",
            "implementation": [
                "Telemetry profile under data/assurance.",
                "Deterministic generator under scripts.",
                "Runtime evaluator for trace-event completeness and redaction decisions.",
                "Generated evidence contract under data/evidence.",
                "Human-readable docs page and MCP tool exposure."
            ],
            "reason": "Enterprise agentic AI buyers need OpenTelemetry-aligned proof that MCP and agent traces are complete enough for audit while safe enough for regulated environments."
        },
        "signal_classes": profile.get("signal_classes", []),
        "source_artifacts": source_artifacts,
        "standards_alignment": profile.get("standards_alignment", []),
        "telemetry_checks": profile.get("telemetry_checks", []),
        "telemetry_contract": profile.get("telemetry_contract", {}),
        "telemetry_summary": build_summary(workflow_contracts, profile, failures),
        "workflow_telemetry_contracts": workflow_contracts,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--measurement-probe-pack", type=Path, default=DEFAULT_MEASUREMENT_PROBE_PACK)
    parser.add_argument("--run-receipt-pack", type=Path, default=DEFAULT_RUN_RECEIPT_PACK)
    parser.add_argument("--egress-boundary-pack", type=Path, default=DEFAULT_EGRESS_BOUNDARY_PACK)
    parser.add_argument("--incident-response-pack", type=Path, default=DEFAULT_INCIDENT_RESPONSE_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in telemetry contract is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    refs = {
        "agentic_measurement_probe_pack": args.measurement_probe_pack,
        "agentic_run_receipt_pack": args.run_receipt_pack,
        "agentic_telemetry_contract_profile": args.profile,
        "agentic_incident_response_pack": args.incident_response_pack,
        "context_egress_boundary_pack": args.egress_boundary_pack,
        "workflow_manifest": args.manifest,
    }
    paths = {key: resolve(repo_root, ref) for key, ref in refs.items()}
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(paths["agentic_telemetry_contract_profile"])
        source_payloads = {
            key: load_json(path)
            for key, path in paths.items()
            if key != "agentic_telemetry_contract_profile"
        }
        failures = [*validate_profile(profile), *validate_sources(source_payloads)]
        pack = build_pack(
            profile=profile,
            source_payloads=source_payloads,
            source_artifacts=build_source_artifacts(repo_root, refs),
            generated_at=args.generated_at,
            failures=failures,
        )
    except TelemetryContractError as exc:
        print(f"agentic telemetry contract generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("agentic telemetry contract validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_agentic_telemetry_contract.py", file=sys.stderr)
            return 1
        if current_text != rendered:
            print(f"{output_path} is stale; run scripts/generate_agentic_telemetry_contract.py", file=sys.stderr)
            return 1
        print(f"Validated agentic telemetry contract: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated agentic telemetry contract with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated agentic telemetry contract: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
