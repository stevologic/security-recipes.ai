#!/usr/bin/env python3
"""Generate the SecurityRecipes model-provider routing pack.

The routing pack answers the enterprise question that appears after
secure context is available and before a model call starts: which
provider/model route may receive this context for this workflow, and
which proof must exist first?
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/model-provider-routing-profile.json")
DEFAULT_WORKFLOW_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_EGRESS_PACK = Path("data/evidence/context-egress-boundary-pack.json")
DEFAULT_TELEMETRY_CONTRACT = Path("data/evidence/agentic-telemetry-contract.json")
DEFAULT_RUN_RECEIPT_PACK = Path("data/evidence/agentic-run-receipt-pack.json")
DEFAULT_OUTPUT = Path("data/evidence/model-provider-routing-pack.json")

REQUIRED_DECISIONS = {
    "allow_approved_route",
    "allow_guarded_route",
    "hold_for_model_provider_review",
    "deny_unapproved_route",
    "kill_session_on_provider_signal",
}
REQUIRED_CONTROLS = {
    "approved_provider_profile",
    "approved_model_route",
    "data_class_allowed",
    "autonomy_within_route_limit",
    "zdr_or_private_runtime_for_sensitive_context",
    "dpa_and_residency_for_external_processors",
    "training_exclusion_for_tenant_context",
    "mcp_gateway_enforcement",
    "tool_and_output_guardrails",
    "redacted_trace_contract",
    "run_receipt_binding",
    "context_egress_decision",
}


class ModelProviderRoutingError(RuntimeError):
    """Raised when the model-provider routing pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ModelProviderRoutingError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ModelProviderRoutingError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ModelProviderRoutingError(f"{path} root must be an object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ModelProviderRoutingError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ModelProviderRoutingError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def normalize_path(path: Path) -> str:
    return path.as_posix()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def sha256_payload(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


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


def source_failure_count(payloads: dict[str, dict[str, Any]]) -> int:
    count = 0
    for payload in payloads.values():
        failures = payload.get("failures")
        if isinstance(failures, list):
            count += len(failures)
    return count


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 140, failures, "profile intent must explain the routing gate goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 10, failures, "standards_alignment must include current AI, MCP, provider, and data-security references")
    seen_standards: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in seen_standards, failures, f"{standard_id}: duplicate standard id")
        seen_standards.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 80, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("decision_contract"), "decision_contract")
    require(
        contract.get("default_decision") == "hold_for_model_provider_review",
        failures,
        "decision contract must fail closed by default",
    )
    decisions = {str(item) for item in as_list(contract.get("valid_decisions"), "valid_decisions")}
    require(REQUIRED_DECISIONS.issubset(decisions), failures, "decision contract is missing required decisions")
    controls = {str(item) for item in as_list(contract.get("required_controls"), "required_controls")}
    require(REQUIRED_CONTROLS.issubset(controls), failures, "decision contract is missing required controls")
    require(len(as_list(contract.get("required_runtime_attributes"), "required_runtime_attributes")) >= 18, failures, "runtime attributes are incomplete")
    require(len(as_list(contract.get("runtime_kill_signals"), "runtime_kill_signals")) >= 8, failures, "runtime kill signals are incomplete")

    providers = as_list(profile.get("provider_profiles"), "provider_profiles")
    routes = as_list(profile.get("model_route_profiles"), "model_route_profiles")
    require(len(providers) >= 4, failures, "at least four provider profiles are required")
    require(len(routes) >= 5, failures, "at least five model route profiles are required")

    provider_ids: set[str] = set()
    for idx, provider in enumerate(providers):
        item = as_dict(provider, f"provider_profiles[{idx}]")
        provider_id = str(item.get("provider_id", "")).strip()
        require(bool(provider_id), failures, f"provider_profiles[{idx}].provider_id is required")
        require(provider_id not in provider_ids, failures, f"{provider_id}: duplicate provider_id")
        provider_ids.add(provider_id)
        require(str(item.get("default_decision")) in REQUIRED_DECISIONS, failures, f"{provider_id}: default_decision is invalid")
        require(str(item.get("status", "")).strip(), failures, f"{provider_id}: status is required")

    route_ids: set[str] = set()
    for idx, route in enumerate(routes):
        item = as_dict(route, f"model_route_profiles[{idx}]")
        route_id = str(item.get("route_id", "")).strip()
        provider_id = str(item.get("provider_id", "")).strip()
        require(bool(route_id), failures, f"model_route_profiles[{idx}].route_id is required")
        require(route_id not in route_ids, failures, f"{route_id}: duplicate route_id")
        route_ids.add(route_id)
        require(provider_id in provider_ids, failures, f"{route_id}: provider_id is unknown")
        require(bool(str(item.get("model_id", "")).strip()), failures, f"{route_id}: model_id is required")
        require(bool(str(item.get("route_class", "")).strip()), failures, f"{route_id}: route_class is required")
        require(isinstance(item.get("allowed_data_classes"), list), failures, f"{route_id}: allowed_data_classes must be a list")
        require(isinstance(item.get("prohibited_data_classes"), list), failures, f"{route_id}: prohibited_data_classes must be a list")
        require(bool(str(item.get("max_autonomy_level", "")).strip()), failures, f"{route_id}: max_autonomy_level is required")
        require(str(item.get("default_decision")) in REQUIRED_DECISIONS, failures, f"{route_id}: default_decision is invalid")

    for idx, override in enumerate(as_list(profile.get("workflow_route_overrides"), "workflow_route_overrides")):
        item = as_dict(override, f"workflow_route_overrides[{idx}]")
        route_refs = [str(route_id) for route_id in as_list(item.get("preferred_route_ids"), f"workflow_route_overrides[{idx}].preferred_route_ids")]
        missing = sorted(set(route_refs) - route_ids)
        require(not missing, failures, f"{item.get('workflow_id')}: unknown preferred route ids {missing}")
    return failures


def validate_sources(sources: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for key, payload in sources.items():
        require(payload.get("schema_version") == SCHEMA_VERSION, failures, f"{key} schema_version must be 1.0")
    require(bool(workflow_by_id(sources["workflow_manifest"])), failures, "workflow manifest must include workflows")
    require(source_failure_count({k: v for k, v in sources.items() if k != "workflow_manifest"}) == 0, failures, "source evidence packs must have zero failures")
    return failures


def route_indexes(profile: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    providers = rows_by_id(as_list(profile.get("provider_profiles"), "provider_profiles"), "provider_id")
    routes = rows_by_id(as_list(profile.get("model_route_profiles"), "model_route_profiles"), "route_id")
    return providers, routes


def override_by_workflow(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return rows_by_id(as_list(profile.get("workflow_route_overrides"), "workflow_route_overrides"), "workflow_id")


def inferred_route_ids(workflow: dict[str, Any]) -> list[str]:
    workflow_id = str(workflow.get("id", ""))
    content = " ".join(
        [
            workflow_id,
            str(workflow.get("title", "")),
            " ".join(str(item) for item in workflow.get("eligible_findings", []) or []),
            " ".join(str(item) for item in workflow.get("kill_signals", []) or []),
        ]
    ).lower()
    if "sensitive" in content or "secret" in content or "sast" in content:
        return ["private-runtime-restricted-route", "tenant-remediation-frontier-route"]
    if "dependency" in content or "base-image" in content or "artifact" in content or "cve" in content:
        return ["tenant-remediation-frontier-route", "public-context-frontier-route"]
    if "browser" in content or "web content" in content:
        return ["browser-and-untrusted-content-guardrail-route"]
    return ["tenant-remediation-frontier-route", "public-context-frontier-route"]


def workflow_data_classes(workflow: dict[str, Any]) -> list[str]:
    workflow_id = str(workflow.get("id", ""))
    content = " ".join(
        [
            workflow_id,
            str(workflow.get("title", "")),
            " ".join(str(item) for item in workflow.get("eligible_findings", []) or []),
        ]
    ).lower()
    classes = {"customer_finding_metadata", "generated_policy_evidence"}
    if any(token in content for token in ["source", "code", "repo", "sast", "dependency", "base-image"]):
        classes.add("customer_source_code")
    if any(token in content for token in ["sensitive", "pii", "secret", "token"]):
        classes.add("customer_asset_metadata")
    if any(token in content for token in ["public", "cve", "vulnerab"]):
        classes.add("public_vulnerability_intelligence")
    return sorted(classes)


def route_preview(route: dict[str, Any], provider: dict[str, Any]) -> dict[str, Any]:
    preview = {
        "allowed_data_classes": route.get("allowed_data_classes", []),
        "default_decision": route.get("default_decision"),
        "dpa_required": route.get("dpa_required"),
        "human_approval_required": route.get("human_approval_required"),
        "max_autonomy_level": route.get("max_autonomy_level"),
        "model_id": route.get("model_id"),
        "provider_id": route.get("provider_id"),
        "provider_status": provider.get("status"),
        "residency_match_required": route.get("residency_match_required"),
        "risk_tier": route.get("risk_tier"),
        "route_class": route.get("route_class"),
        "route_id": route.get("route_id"),
        "title": route.get("title"),
        "zero_data_retention_required": route.get("zero_data_retention_required"),
    }
    preview["route_hash"] = sha256_payload(preview)
    return preview


def build_workflow_route_matrix(
    profile: dict[str, Any],
    workflow_manifest: dict[str, Any],
) -> list[dict[str, Any]]:
    providers, routes = route_indexes(profile)
    overrides = override_by_workflow(profile)
    rows: list[dict[str, Any]] = []
    for workflow_id, workflow in sorted(workflow_by_id(workflow_manifest).items()):
        override = overrides.get(workflow_id, {})
        selected_ids = [str(item) for item in override.get("preferred_route_ids", [])] or inferred_route_ids(workflow)
        selected_routes = [
            route_preview(routes[route_id], providers[str(routes[route_id].get("provider_id"))])
            for route_id in selected_ids
            if route_id in routes and str(routes[route_id].get("provider_id")) in providers
        ]
        minimum_controls = [str(item) for item in override.get("minimum_controls", [])]
        if not minimum_controls:
            minimum_controls = [
                "enterprise_contract",
                "training_opt_out",
                "mcp_gateway_enforced",
                "tool_guardrails_enforced",
                "telemetry_redacted",
                "run_receipt_attached",
                "egress_decision_allow",
            ]
        row = {
            "data_classes": workflow_data_classes(workflow),
            "default_decision": "hold_for_model_provider_review" if not selected_routes else selected_routes[0]["default_decision"],
            "minimum_controls": sorted(set(minimum_controls)),
            "notes": override.get("notes", "Use the first preferred route that satisfies runtime data-class, autonomy, provider-contract, egress, receipt, telemetry, and approval evidence."),
            "preferred_route_ids": [route["route_id"] for route in selected_routes],
            "route_count": len(selected_routes),
            "routes": selected_routes,
            "status": workflow.get("status"),
            "title": workflow.get("title"),
            "workflow_id": workflow_id,
        }
        row["workflow_route_hash"] = sha256_payload(row)
        rows.append(row)
    return rows


def source_artifacts(repo_root: Path, paths: dict[str, Path]) -> list[dict[str, str]]:
    artifacts: list[dict[str, str]] = []
    for label, path in paths.items():
        resolved = resolve(repo_root, path)
        artifacts.append(
            {
                "id": label,
                "path": normalize_path(path),
                "sha256": sha256_file(resolved),
            }
        )
    return artifacts


def build_pack(
    *,
    profile: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    source_paths: dict[str, Path],
    repo_root: Path,
) -> dict[str, Any]:
    failures = validate_profile(profile)
    failures.extend(validate_sources(sources))
    providers, routes = route_indexes(profile)
    workflow_matrix = build_workflow_route_matrix(profile, sources["workflow_manifest"])
    decision_counts = Counter(str(route.get("default_decision")) for route in routes.values())
    risk_counts = Counter(str(route.get("risk_tier")) for route in routes.values())
    provider_status_counts = Counter(str(provider.get("status")) for provider in providers.values())

    return {
        "commercialization_path": profile.get("commercialization_path", {}),
        "decision_contract": profile.get("decision_contract", {}),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "evaluator_contract": {
            "decision_order": [
                "kill_session_on_provider_signal",
                "deny_unapproved_route",
                "hold_for_model_provider_review",
                "allow_guarded_route",
                "allow_approved_route",
            ],
            "default_decision_for_missing_fields": "hold_for_model_provider_review",
            "route_match_keys": ["route_id", "provider_id", "model_id", "route_class"],
        },
        "failures": failures,
        "generated_at": date.today().isoformat(),
        "intent": profile.get("intent"),
        "model_provider_routing_summary": {
            "decision_counts": dict(sorted(decision_counts.items())),
            "provider_count": len(providers),
            "provider_status_counts": dict(sorted(provider_status_counts.items())),
            "risk_tier_counts": dict(sorted(risk_counts.items())),
            "route_count": len(routes),
            "workflow_count": len(workflow_matrix),
        },
        "model_route_profiles": [
            route_preview(route, providers[str(route.get("provider_id"))])
            for route in sorted(routes.values(), key=lambda item: str(item.get("route_id")))
        ],
        "positioning": profile.get("positioning", {}),
        "provider_profiles": [
            provider
            for provider in sorted(providers.values(), key=lambda item: str(item.get("provider_id")))
        ],
        "residual_risks": profile.get("residual_risks", []),
        "schema_version": SCHEMA_VERSION,
        "scoring_model": profile.get("scoring_model", {}),
        "selected_feature": {
            "id": "model-provider-routing-gate",
            "implementation": [
                "Provider-routing profile under data/assurance.",
                "Deterministic generator under scripts.",
                "Runtime evaluator for provider/model/data/autonomy/evidence decisions.",
                "Generated evidence pack under data/evidence.",
                "Human-readable docs page and MCP tool exposure."
            ],
            "reason": "Enterprise buyers need a provider-neutral gate that proves which model route may receive secure context before a tool-capable agent starts a model call."
        },
        "source_artifacts": source_artifacts(repo_root, source_paths),
        "standards_alignment": profile.get("standards_alignment", []),
        "workflow_route_matrix": workflow_matrix,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--workflow-manifest", type=Path, default=DEFAULT_WORKFLOW_MANIFEST)
    parser.add_argument("--egress-pack", type=Path, default=DEFAULT_EGRESS_PACK)
    parser.add_argument("--telemetry-contract", type=Path, default=DEFAULT_TELEMETRY_CONTRACT)
    parser.add_argument("--run-receipt-pack", type=Path, default=DEFAULT_RUN_RECEIPT_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="Fail if the generated output differs from the committed artifact.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo_root = Path(__file__).resolve().parents[1]
    source_paths = {
        "profile": args.profile,
        "workflow_manifest": args.workflow_manifest,
        "context_egress_boundary_pack": args.egress_pack,
        "agentic_telemetry_contract": args.telemetry_contract,
        "agentic_run_receipt_pack": args.run_receipt_pack,
    }
    profile = load_json(resolve(repo_root, args.profile))
    sources = {
        "workflow_manifest": load_json(resolve(repo_root, args.workflow_manifest)),
        "context_egress_boundary_pack": load_json(resolve(repo_root, args.egress_pack)),
        "agentic_telemetry_contract": load_json(resolve(repo_root, args.telemetry_contract)),
        "agentic_run_receipt_pack": load_json(resolve(repo_root, args.run_receipt_pack)),
    }
    pack = build_pack(
        profile=profile,
        sources=sources,
        source_paths=source_paths,
        repo_root=repo_root,
    )
    rendered = stable_json(pack)
    output_path = resolve(repo_root, args.output)

    if args.check:
        try:
            current = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{args.output} does not exist", file=sys.stderr)
            return 1
        if current != rendered:
            print(f"{args.output} is stale; run scripts/generate_model_provider_routing_pack.py", file=sys.stderr)
            return 1
        return 0 if not pack["failures"] else 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if pack["failures"]:
        print("generated model provider routing pack with validation failures:", file=sys.stderr)
        for failure in pack["failures"]:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
