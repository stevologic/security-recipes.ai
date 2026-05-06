#!/usr/bin/env python3
"""Generate the SecurityRecipes MCP tool-surface drift pack.

This pack pins approved MCP tool descriptions, schemas, annotations, and
capability metadata. It gives an agent host or MCP gateway a deterministic
baseline for deciding whether a live tool surface is unchanged, reviewable,
unsafe, or a kill-session event.
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
DEFAULT_PROFILE = Path("data/assurance/mcp-tool-surface-drift-profile.json")
DEFAULT_CONNECTOR_TRUST_PACK = Path("data/evidence/mcp-connector-trust-pack.json")
DEFAULT_CONNECTOR_INTAKE_PACK = Path("data/evidence/mcp-connector-intake-pack.json")
DEFAULT_TOOL_RISK_CONTRACT = Path("data/evidence/mcp-tool-risk-contract.json")
DEFAULT_AUTHORIZATION_PACK = Path("data/evidence/mcp-authorization-conformance-pack.json")
DEFAULT_OUTPUT = Path("data/evidence/mcp-tool-surface-drift-pack.json")

VALID_SOURCE_KINDS = {"registered_connector", "candidate_connector", "denied_candidate"}
VALID_DECISIONS = {
    "allow_pinned_tool_surface",
    "allow_reviewed_tool_surface",
    "hold_for_tool_surface_review",
    "deny_tool_surface_regression",
    "deny_unregistered_tool_surface",
    "kill_session_on_tool_surface_signal",
}
HIGH_IMPACT_FLAGS = {
    "approval_required",
    "branch_write",
    "external_message",
    "funds_movement",
    "high_impact_action",
    "private_network",
    "quarantine_staging",
    "state_changing",
}


class ToolSurfaceDriftPackError(RuntimeError):
    """Raised when the tool-surface drift pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ToolSurfaceDriftPackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ToolSurfaceDriftPackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ToolSurfaceDriftPackError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ToolSurfaceDriftPackError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ToolSurfaceDriftPackError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def stable_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def text_hash(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def normalize_path(path: Path) -> str:
    return path.as_posix()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def connector_by_namespace(connector_trust_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(connector.get("namespace")): connector
        for connector in as_list(connector_trust_pack.get("connectors"), "connector_trust_pack.connectors")
        if isinstance(connector, dict) and connector.get("namespace")
    }


def candidate_by_namespace(connector_intake_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(candidate.get("namespace")): candidate
        for candidate in as_list(connector_intake_pack.get("candidate_evaluations"), "connector_intake_pack.candidate_evaluations")
        if isinstance(candidate, dict) and candidate.get("namespace")
    }


def tool_risk_by_namespace(tool_risk_contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(profile.get("namespace")): profile
        for profile in as_list(tool_risk_contract.get("tool_profiles"), "tool_risk_contract.tool_profiles")
        if isinstance(profile, dict) and profile.get("namespace")
    }


def authorization_by_namespace(authorization_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = []
    rows.extend(authorization_pack.get("registered_connector_authorization", []) or [])
    rows.extend(authorization_pack.get("candidate_authorization", []) or [])
    return {
        str(row.get("namespace")): row
        for row in rows
        if isinstance(row, dict) and row.get("namespace")
    }


def normalize_bool_map(value: dict[str, Any]) -> dict[str, bool]:
    output: dict[str, bool] = {}
    for key, item in value.items():
        output[str(key)] = bool(item)
    return dict(sorted(output.items()))


def source_record_for(
    surface: dict[str, Any],
    connectors: dict[str, dict[str, Any]],
    candidates: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    namespace = str(surface.get("namespace"))
    source_kind = str(surface.get("source_kind"))
    if source_kind == "registered_connector":
        return connectors.get(namespace)
    if source_kind in {"candidate_connector", "denied_candidate"}:
        return candidates.get(namespace)
    return None


def validate_profile(
    profile: dict[str, Any],
    connectors: dict[str, dict[str, Any]],
    candidates: dict[str, dict[str, Any]],
) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must explain tool-surface drift")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 7, failures, "standards_alignment must include MCP, OWASP, and NIST references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in standard_ids, failures, f"{standard_id}: duplicate standard id")
        standard_ids.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 70, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("drift_contract"), "drift_contract")
    require(contract.get("default_decision") == "hold_for_tool_surface_review", failures, "default decision must fail closed")
    decisions = {str(decision) for decision in as_list(contract.get("allowed_decisions"), "drift_contract.allowed_decisions")}
    require(VALID_DECISIONS.issubset(decisions), failures, "allowed decisions are incomplete")
    require(len(as_list(contract.get("review_required_for"), "drift_contract.review_required_for")) >= 8, failures, "review triggers are incomplete")
    require(len(as_list(contract.get("kill_signals"), "drift_contract.kill_signals")) >= 5, failures, "kill signals are incomplete")

    control_checks = as_list(profile.get("control_checks"), "control_checks")
    require(len(control_checks) >= 7, failures, "control_checks must cover hashes, capability expansion, workflow binding, and signed baselines")

    surfaces = as_list(profile.get("baseline_tool_surfaces"), "baseline_tool_surfaces")
    require(len(surfaces) >= 6, failures, "at least six baseline tool surfaces are required")
    seen_ids: set[str] = set()
    seen_tool_keys: set[tuple[str, str]] = set()
    required_fields = {str(field) for field in as_list(contract.get("required_surface_fields"), "drift_contract.required_surface_fields")}
    for idx, surface in enumerate(surfaces):
        item = as_dict(surface, f"baseline_tool_surfaces[{idx}]")
        surface_id = str(item.get("id", "")).strip()
        namespace = str(item.get("namespace", "")).strip()
        tool_name = str(item.get("tool_name", "")).strip()
        source_kind = str(item.get("source_kind", "")).strip()

        require(bool(surface_id), failures, f"baseline_tool_surfaces[{idx}].id is required")
        require(surface_id not in seen_ids, failures, f"{surface_id}: duplicate surface id")
        seen_ids.add(surface_id)
        require(bool(namespace), failures, f"{surface_id}: namespace is required")
        require(bool(tool_name), failures, f"{surface_id}: tool_name is required")
        require((namespace, tool_name) not in seen_tool_keys, failures, f"{surface_id}: duplicate namespace/tool_name")
        seen_tool_keys.add((namespace, tool_name))
        require(source_kind in VALID_SOURCE_KINDS, failures, f"{surface_id}: source_kind is invalid")

        missing_fields = sorted(field for field in required_fields if field not in item)
        require(not missing_fields, failures, f"{surface_id}: missing required fields {missing_fields}")
        require(bool(source_record_for(item, connectors, candidates)), failures, f"{surface_id}: namespace is not present in connector trust or intake packs")
        require(bool(as_list(item.get("allowed_workflow_ids"), f"{surface_id}.allowed_workflow_ids")), failures, f"{surface_id}: allowed_workflow_ids are required")
        require(isinstance(item.get("input_schema"), dict), failures, f"{surface_id}: input_schema must be an object")
        require(isinstance(item.get("output_schema"), dict), failures, f"{surface_id}: output_schema must be an object")
        require(isinstance(item.get("annotations"), dict), failures, f"{surface_id}: annotations must be an object")
        require(str(item.get("access_mode", "")).strip(), failures, f"{surface_id}: access_mode is required")
        require(bool(as_list(item.get("capability_flags"), f"{surface_id}.capability_flags")), failures, f"{surface_id}: capability_flags are required")
        require(len(str(item.get("description", ""))) >= 80, failures, f"{surface_id}: description must be specific")

    return failures


def validate_sources(sources: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for key, payload in sources.items():
        require(payload.get("schema_version") == PACK_SCHEMA_VERSION, failures, f"{key} schema_version must be 1.0")
    require(bool(sources["mcp_connector_trust_pack"].get("connectors")), failures, "connector trust pack must include connectors")
    require(bool(sources["mcp_connector_intake_pack"].get("candidate_evaluations")), failures, "connector intake pack must include candidate evaluations")
    require(bool(sources["mcp_tool_risk_contract"].get("tool_profiles")), failures, "tool-risk contract must include tool profiles")
    require(bool(sources["mcp_authorization_conformance_pack"].get("registered_connector_authorization")), failures, "authorization pack must include registered connector authorization")
    return failures


def build_surface_baseline(
    surface: dict[str, Any],
    source_record: dict[str, Any] | None,
    tool_risk_profile: dict[str, Any] | None,
    authorization_profile: dict[str, Any] | None,
) -> dict[str, Any]:
    annotations = normalize_bool_map(as_dict(surface.get("annotations"), f"{surface.get('id')}.annotations"))
    description_hash = text_hash(str(surface.get("description", "")))
    input_schema_hash = stable_hash(surface.get("input_schema", {}))
    output_schema_hash = stable_hash(surface.get("output_schema", {}))
    annotations_hash = stable_hash(annotations)
    source_kind = str(surface.get("source_kind"))
    capability_flags = sorted(str(flag) for flag in surface.get("capability_flags", []) or [])
    high_impact = bool(HIGH_IMPACT_FLAGS & set(capability_flags))

    source_status = source_record.get("status") or source_record.get("requested_status") if source_record else None
    source_decision = source_record.get("intake_decision") if source_record else None
    trust_tier = source_record.get("trust_tier") if source_record else None
    if isinstance(trust_tier, dict):
        trust_tier = trust_tier.get("id")

    surface_hash_payload = {
        "access_mode": surface.get("access_mode"),
        "annotations_sha256": annotations_hash,
        "capability_flags": capability_flags,
        "data_classes": sorted(str(item) for item in surface.get("data_classes", []) or []),
        "description_sha256": description_hash,
        "external_systems": sorted(str(item) for item in surface.get("external_systems", []) or []),
        "input_schema_sha256": input_schema_hash,
        "namespace": surface.get("namespace"),
        "output_schema_sha256": output_schema_hash,
        "tool_name": surface.get("tool_name"),
    }

    return {
        "access_mode": surface.get("access_mode"),
        "allowed_workflow_ids": surface.get("allowed_workflow_ids", []),
        "annotations": annotations,
        "annotations_sha256": annotations_hash,
        "authorization_decision": authorization_profile.get("conformance_decision") if authorization_profile else None,
        "capability_flags": capability_flags,
        "connector_id": surface.get("connector_id"),
        "connector_status": source_status,
        "data_classes": surface.get("data_classes", []),
        "default_runtime_decision": (
            "hold_for_tool_surface_review"
            if source_kind != "registered_connector" or source_decision
            else "allow_pinned_tool_surface"
        ),
        "description": surface.get("description"),
        "description_sha256": description_hash,
        "external_systems": surface.get("external_systems", []),
        "high_impact_surface": high_impact,
        "id": surface.get("id"),
        "input_schema": surface.get("input_schema"),
        "input_schema_sha256": input_schema_hash,
        "namespace": surface.get("namespace"),
        "output_schema": surface.get("output_schema"),
        "output_schema_sha256": output_schema_hash,
        "review_cadence": surface.get("review_cadence"),
        "risk_tier": surface.get("risk_tier") or (tool_risk_profile or {}).get("risk_tier"),
        "source_decision": source_decision,
        "source_kind": source_kind,
        "surface_hash": stable_hash(surface_hash_payload),
        "title": surface.get("title"),
        "tool_name": surface.get("tool_name"),
        "tool_risk_default_decision": (tool_risk_profile or {}).get("default_runtime_decision"),
        "tool_risk_factors": (tool_risk_profile or {}).get("risk_factors"),
        "trust_tier": trust_tier,
    }


def build_sample_decisions(surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(surface.get("id")): surface for surface in surfaces}
    repo = by_id.get("repo-contents-patch-scoped-branch", {})
    advisory = by_id.get("advisories-vulnerability-read", {})
    registry = by_id.get("registries-quarantine-stage-plan", {})
    browser = by_id.get("browser-research-fetch-url-candidate", {})
    return [
        {
            "id": "pinned-repo-branch-write",
            "decision": "allow_pinned_tool_surface",
            "expected_runtime_request": {
                "namespace": repo.get("namespace"),
                "tool_name": repo.get("tool_name"),
                "description_sha256": repo.get("description_sha256"),
                "input_schema_sha256": repo.get("input_schema_sha256"),
                "output_schema_sha256": repo.get("output_schema_sha256"),
                "annotations_sha256": repo.get("annotations_sha256")
            },
            "why": "The live tool surface matches the pinned baseline for a registered connector."
        },
        {
            "id": "advisory-description-drift",
            "decision": "hold_for_tool_surface_review",
            "expected_runtime_request": {
                "namespace": advisory.get("namespace"),
                "tool_name": advisory.get("tool_name"),
                "description_sha256": "sha256:changed-description"
            },
            "why": "Description drift changes prompt-layer input and requires review before the agent can trust the tool."
        },
        {
            "id": "registry-capability-expansion",
            "decision": "kill_session_on_tool_surface_signal",
            "expected_runtime_request": {
                "namespace": registry.get("namespace"),
                "tool_name": registry.get("tool_name"),
                "capability_expansion": True,
                "added_capability_flags": [
                    "delete",
                    "publish",
                    "production_credential"
                ]
            },
            "why": "High-impact capability expansion after approval invalidates the session."
        },
        {
            "id": "candidate-browser-tool",
            "decision": "hold_for_tool_surface_review",
            "expected_runtime_request": {
                "namespace": browser.get("namespace"),
                "tool_name": browser.get("tool_name"),
                "description_sha256": browser.get("description_sha256")
            },
            "why": "Candidate connector surfaces can be fingerprinted, but they are not production-allowed by default."
        }
    ]


def build_summary(surfaces: list[dict[str, Any]], failures: list[str]) -> dict[str, Any]:
    source_counts = Counter(str(surface.get("source_kind")) for surface in surfaces)
    decisions = Counter(str(surface.get("default_runtime_decision")) for surface in surfaces)
    namespaces = {str(surface.get("namespace")) for surface in surfaces}
    high_impact_count = sum(1 for surface in surfaces if surface.get("high_impact_surface"))
    return {
        "default_decision_counts": dict(sorted(decisions.items())),
        "failure_count": len(failures),
        "high_impact_surface_count": high_impact_count,
        "namespace_count": len(namespaces),
        "source_kind_counts": dict(sorted(source_counts.items())),
        "status": "drift_baseline_ready" if not failures else "needs_attention",
        "surface_count": len(surfaces),
    }


def build_source_artifacts(repo_root: Path, refs: dict[str, Path]) -> dict[str, dict[str, str]]:
    return {
        key: {
            "path": normalize_path(ref),
            "sha256": sha256_file(resolve(repo_root, ref)),
        }
        for key, ref in sorted(refs.items())
    }


def build_pack(
    *,
    profile: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    source_artifacts: dict[str, dict[str, str]],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    connectors = connector_by_namespace(sources["mcp_connector_trust_pack"])
    candidates = candidate_by_namespace(sources["mcp_connector_intake_pack"])
    tool_risk = tool_risk_by_namespace(sources["mcp_tool_risk_contract"])
    authorization = authorization_by_namespace(sources["mcp_authorization_conformance_pack"])
    surfaces = [
        build_surface_baseline(
            surface=surface,
            source_record=source_record_for(surface, connectors, candidates),
            tool_risk_profile=tool_risk.get(str(surface.get("namespace"))),
            authorization_profile=authorization.get(str(surface.get("namespace"))),
        )
        for surface in as_list(profile.get("baseline_tool_surfaces"), "baseline_tool_surfaces")
        if isinstance(surface, dict)
    ]
    surfaces = sorted(surfaces, key=lambda item: (str(item.get("namespace")), str(item.get("tool_name"))))
    return {
        "control_checks": profile.get("control_checks", []),
        "drift_contract": profile.get("drift_contract", {}),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "This public pack fingerprints declared and example tool surfaces; it does not observe a customer's live MCP fleet.",
                "treatment": "Use the runtime evaluator locally, then sell hosted fleet monitoring, signed baselines, and customer-specific diff alerts."
            },
            {
                "risk": "A malicious MCP server can return safe metadata during review and different behavior at runtime.",
                "treatment": "Bind tool-surface checks to gateway enforcement, runtime tool-result inspection, authorization decisions, and run receipts."
            },
            {
                "risk": "Annotations and schemas alone do not prove tool behavior.",
                "treatment": "Treat hashes as drift evidence, then require sandboxing, least privilege, output validation, and human approval for sensitive tools."
            }
        ],
        "sample_runtime_decisions": build_sample_decisions(surfaces),
        "schema_version": PACK_SCHEMA_VERSION,
        "selected_feature": {
            "id": "mcp-tool-surface-drift-sentinel",
            "implementation": [
                "Source-controlled tool-surface drift profile under data/assurance.",
                "Dependency-free generator with --check mode.",
                "Generated evidence pack under data/evidence.",
                "Runtime evaluator for allow, hold, deny, and kill-session decisions.",
                "Human-readable documentation and MCP server exposure."
            ],
            "reason": "Enterprise MCP buyers need continuous assurance that approved tools did not change descriptions, schemas, annotations, or capabilities after intake."
        },
        "source_artifacts": source_artifacts,
        "standards_alignment": profile.get("standards_alignment", []),
        "tool_surface_summary": build_summary(surfaces, failures),
        "tool_surfaces": surfaces,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--connector-trust-pack", type=Path, default=DEFAULT_CONNECTOR_TRUST_PACK)
    parser.add_argument("--connector-intake-pack", type=Path, default=DEFAULT_CONNECTOR_INTAKE_PACK)
    parser.add_argument("--tool-risk-contract", type=Path, default=DEFAULT_TOOL_RISK_CONTRACT)
    parser.add_argument("--authorization-pack", type=Path, default=DEFAULT_AUTHORIZATION_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in drift pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    refs = {
        "mcp_authorization_conformance_pack": args.authorization_pack,
        "mcp_connector_intake_pack": args.connector_intake_pack,
        "mcp_connector_trust_pack": args.connector_trust_pack,
        "mcp_tool_risk_contract": args.tool_risk_contract,
        "mcp_tool_surface_drift_profile": args.profile,
    }
    paths = {key: resolve(repo_root, ref) for key, ref in refs.items()}
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(paths["mcp_tool_surface_drift_profile"])
        sources = {
            key: load_json(path)
            for key, path in paths.items()
            if key != "mcp_tool_surface_drift_profile"
        }
        connectors = connector_by_namespace(sources["mcp_connector_trust_pack"])
        candidates = candidate_by_namespace(sources["mcp_connector_intake_pack"])
        failures = [
            *validate_sources(sources),
            *validate_profile(profile, connectors, candidates),
        ]
        pack = build_pack(
            profile=profile,
            sources=sources,
            source_artifacts=build_source_artifacts(repo_root, refs),
            generated_at=args.generated_at,
            failures=failures,
        )
    except ToolSurfaceDriftPackError as exc:
        print(f"MCP tool-surface drift pack generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("MCP tool-surface drift pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != rendered:
            print(f"{output_path} is stale; run scripts/generate_mcp_tool_surface_drift_pack.py", file=sys.stderr)
            return 1
        print(f"Validated MCP tool-surface drift pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated MCP tool-surface drift pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated MCP tool-surface drift pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
