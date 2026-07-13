#!/usr/bin/env python3
"""Generate the SecurityRecipes MCP tool-risk contract.

The contract turns MCP tool annotations into a governed risk signal
without treating those annotations as enforcement. It combines connector
trust, authorization conformance, workflow scope, and session-combination
risk so an agent host or MCP gateway can decide whether a tool call is
safe enough to proceed.
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
DEFAULT_PROFILE = Path("data/assurance/mcp-tool-risk-contract-profile.json")
DEFAULT_CONNECTOR_TRUST_PACK = Path("data/evidence/mcp-connector-trust-pack.json")
DEFAULT_AUTHORIZATION_PACK = Path("data/evidence/mcp-authorization-conformance-pack.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_GATEWAY_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_OUTPUT = Path("data/evidence/mcp-tool-risk-contract.json")

READ_ACCESS_MODES = {"read"}
WRITE_ACCESS_MODES = {"write_branch", "write_ticket", "approval_required"}
EXTERNAL_WRITE_ACCESS_MODES = {"write_ticket", "approval_required"}
DESTRUCTIVE_TERMS = {
    "delete",
    "destroy",
    "purge",
    "quarantine",
    "submit transaction",
    "broadcast",
    "deploy",
    "publish",
    "release",
    "wallet",
    "signer",
    "multisig",
}
PRIVATE_MARKERS = {
    "artifact_inventory",
    "build_status",
    "customer",
    "data_classification",
    "fork_test_result",
    "invariant_test_result",
    "identity",
    "incident",
    "internal",
    "log",
    "package_inventory",
    "payment",
    "policy",
    "read_only_rpc_trace",
    "repo",
    "scanner",
    "scanner_artifacts",
    "secret",
    "source",
    "ticket",
    "token",
    "trace",
    "wallet",
}
UNTRUSTED_MARKERS = {
    "advisory",
    "artifact",
    "cve",
    "finding",
    "fork_test_result",
    "invariant_test_result",
    "log",
    "package",
    "read_only_rpc_trace",
    "scanner",
    "source",
    "ticket",
}


class ToolRiskContractError(RuntimeError):
    """Raised when the MCP tool-risk contract cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ToolRiskContractError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ToolRiskContractError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ToolRiskContractError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ToolRiskContractError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ToolRiskContractError(f"{label} must be a list")
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


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must explain the product goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 9, failures, "standards_alignment must include MCP, OWASP, NIST, and A2A references")
    seen: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in seen, failures, f"{standard_id}: duplicate standard id")
        seen.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 70, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("tool_risk_contract"), "tool_risk_contract")
    require(
        contract.get("default_decision") == "hold_for_tool_risk_review",
        failures,
        "tool risk contract default decision must fail closed",
    )
    required_annotations = {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}
    declared_annotations = {str(item) for item in as_list(contract.get("standard_tool_annotations"), "standard_tool_annotations")}
    require(required_annotations.issubset(declared_annotations), failures, "standard tool annotations are incomplete")
    defaults = as_dict(contract.get("standard_annotation_defaults"), "standard_annotation_defaults")
    require(defaults.get("readOnlyHint") is False, failures, "readOnlyHint default must be false")
    require(defaults.get("destructiveHint") is True, failures, "destructiveHint default must be true")
    require(defaults.get("idempotentHint") is False, failures, "idempotentHint default must be false")
    require(defaults.get("openWorldHint") is True, failures, "openWorldHint default must be true")
    require(
        len(as_list(contract.get("required_runtime_attributes"), "required_runtime_attributes")) >= 12,
        failures,
        "required_runtime_attributes must include workflow, run, server, policy, and authorization evidence",
    )
    require(
        len(as_list(profile.get("risk_tiers"), "risk_tiers")) >= 5,
        failures,
        "risk_tiers must include context, untrusted, private, state-changing, and destructive tiers",
    )
    require(
        len(as_list(profile.get("control_checks"), "control_checks")) >= 8,
        failures,
        "control_checks must cover annotation trust, output validation, combination risk, and scope drift",
    )
    return failures


def validate_sources(sources: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for key, payload in sources.items():
        require(payload.get("schema_version") == "1.0", failures, f"{key} schema_version must be 1.0")
    require(not sources["mcp_connector_trust_pack"].get("failures"), failures, "connector trust pack must have zero failures")
    require(not sources["mcp_authorization_conformance_pack"].get("failures"), failures, "authorization conformance pack must have zero failures")
    require(not sources["mcp_gateway_policy"].get("failures"), failures, "gateway policy pack must have zero failures")
    return failures


def stable_hash(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def row_by_namespace(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("namespace")): row
        for row in rows
        if isinstance(row, dict) and row.get("namespace")
    }


def connector_rows(connector_trust_pack: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        connector
        for connector in as_list(connector_trust_pack.get("connectors"), "mcp_connector_trust_pack.connectors")
        if isinstance(connector, dict)
    ]


def workflow_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        workflow
        for workflow in as_list(manifest.get("workflows"), "workflow_manifest.workflows")
        if isinstance(workflow, dict)
    ]


def policies_by_workflow(policy_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(policy.get("workflow_id")): policy
        for policy in as_list(policy_pack.get("workflow_policies"), "mcp_gateway_policy.workflow_policies")
        if isinstance(policy, dict) and policy.get("workflow_id")
    }


def authorization_by_namespace(authorization_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = []
    rows.extend(authorization_pack.get("registered_connector_authorization", []) or [])
    rows.extend(authorization_pack.get("candidate_authorization", []) or [])
    return row_by_namespace(rows)


def tier_id(connector: dict[str, Any]) -> str:
    tier = connector.get("trust_tier")
    if isinstance(tier, dict):
        return str(tier.get("id") or "")
    return str(tier or "")


def text_blob(connector: dict[str, Any]) -> str:
    fields = [
        connector.get("namespace"),
        connector.get("connector_id"),
        connector.get("title"),
        connector.get("category"),
        *(connector.get("data_classes") or []),
        *(connector.get("allowed_operations") or []),
        *(connector.get("forbidden_operations") or []),
        *(connector.get("kill_signals") or []),
    ]
    return " ".join(str(field).lower() for field in fields if field is not None)


def allowed_operation_blob(connector: dict[str, Any]) -> str:
    fields = [
        connector.get("namespace"),
        connector.get("connector_id"),
        connector.get("title"),
        connector.get("category"),
        *(connector.get("data_classes") or []),
        *(connector.get("allowed_operations") or []),
    ]
    return " ".join(str(field).lower() for field in fields if field is not None)


def contains_any(text: str, markers: set[str]) -> bool:
    return any(marker in text for marker in markers)


def access_modes(connector: dict[str, Any]) -> set[str]:
    return {str(mode) for mode in connector.get("access_modes", []) or []}


def infer_risk_factors(connector: dict[str, Any]) -> dict[str, bool]:
    modes = access_modes(connector)
    blob = text_blob(connector)
    allowed_blob = allowed_operation_blob(connector)
    writes_state = bool(modes & WRITE_ACCESS_MODES)
    destructive = "approval_required" in modes or contains_any(allowed_blob, DESTRUCTIVE_TERMS)
    reads_private = tier_id(connector) != "tier_0_public_context" and contains_any(blob, PRIVATE_MARKERS)
    sees_untrusted = contains_any(blob, UNTRUSTED_MARKERS) or str(connector.get("category")) in {
        "risk_and_finding_sources",
        "code_and_build_sources",
        "observability_and_telemetry_sources",
    }
    can_exfiltrate = bool(modes & EXTERNAL_WRITE_ACCESS_MODES) or str(connector.get("namespace", "")).startswith("tickets.")
    requires_human_approval = "approval_required" in modes or destructive
    return {
        "can_exfiltrate": can_exfiltrate,
        "destructive_action_potential": destructive,
        "reads_private_data": reads_private,
        "requires_human_approval": requires_human_approval,
        "sees_untrusted_content": sees_untrusted,
        "writes_state": writes_state,
    }


def risk_tier_for(factors: dict[str, bool]) -> str:
    if factors["destructive_action_potential"] or (
        factors["can_exfiltrate"] and (factors["reads_private_data"] or factors["sees_untrusted_content"])
    ):
        return "tier_4_destructive_or_exfiltration"
    if factors["writes_state"]:
        return "tier_3_state_changing"
    if factors["reads_private_data"]:
        return "tier_2_private_context"
    if factors["sees_untrusted_content"]:
        return "tier_1_read_untrusted"
    return "tier_0_context_only"


def suggested_annotations(connector: dict[str, Any], factors: dict[str, bool]) -> dict[str, bool]:
    modes = access_modes(connector)
    read_only = bool(modes) and modes.issubset(READ_ACCESS_MODES)
    return {
        "destructiveHint": bool(factors["destructive_action_potential"]),
        "idempotentHint": read_only,
        "openWorldHint": True,
        "readOnlyHint": read_only,
    }


def default_decision_for(profile: dict[str, Any], tier: str, factors: dict[str, bool]) -> str:
    if factors["destructive_action_potential"]:
        return "hold_for_tool_risk_review"
    for risk_tier in profile.get("risk_tiers", []):
        if isinstance(risk_tier, dict) and risk_tier.get("id") == tier:
            return str(risk_tier.get("default_decision"))
    return "hold_for_tool_risk_review"


def build_tool_profile(
    *,
    connector: dict[str, Any],
    authorization: dict[str, Any] | None,
    profile: dict[str, Any],
) -> dict[str, Any]:
    factors = infer_risk_factors(connector)
    tier = risk_tier_for(factors)
    namespace = str(connector.get("namespace"))
    controls = set(str(control) for control in connector.get("required_controls", []) or [])
    trusted_server = connector.get("status") == "production" and bool(
        {"pin_tool_descriptions", "audit_every_tool_call", "session_binding"} & controls
    )
    return {
        "access_modes": sorted(access_modes(connector)),
        "annotation_source": "trusted_enterprise_gateway" if trusted_server else "untrusted_or_unverified_server",
        "authorization_decision": authorization.get("conformance_decision") if authorization else None,
        "connector_id": connector.get("connector_id"),
        "control_gaps": authorization.get("control_gaps", []) if authorization else [],
        "data_classes": connector.get("data_classes", []),
        "default_runtime_decision": default_decision_for(profile, tier, factors),
        "deployment_model": connector.get("deployment_model"),
        "forbidden_operations": connector.get("forbidden_operations", []),
        "namespace": namespace,
        "owner": connector.get("owner"),
        "required_controls": sorted(controls),
        "risk_factors": factors,
        "risk_tier": tier,
        "status": connector.get("status"),
        "suggested_annotations": suggested_annotations(connector, factors),
        "title": connector.get("title"),
        "tool_profile_id": f"mcp-tool-risk::{namespace}",
        "transport": connector.get("transport"),
        "trusted_server": trusted_server,
        "trust_tier": connector.get("trust_tier"),
    }


def namespaces_by_workflow(manifest: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = {}
    for workflow in workflow_rows(manifest):
        rows = []
        for context in workflow.get("mcp_context", []) or []:
            if isinstance(context, dict) and context.get("namespace"):
                rows.append(context)
        output[str(workflow.get("id"))] = rows
    return output


def build_workflow_risk_rows(
    *,
    manifest: dict[str, Any],
    gateway_policy: dict[str, Any],
    tool_profiles: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_namespace = {str(row.get("namespace")): row for row in tool_profiles}
    policies = policies_by_workflow(gateway_policy)
    workflow_contexts = namespaces_by_workflow(manifest)
    rows: list[dict[str, Any]] = []
    for workflow in workflow_rows(manifest):
        workflow_id = str(workflow.get("id"))
        namespaces = []
        aggregate = {
            "can_exfiltrate": False,
            "destructive_action_potential": False,
            "reads_private_data": False,
            "requires_human_approval": False,
            "sees_untrusted_content": False,
            "writes_state": False,
        }
        for context in workflow_contexts.get(workflow_id, []):
            namespace = str(context.get("namespace"))
            tool_profile = by_namespace.get(namespace, {})
            factors = tool_profile.get("risk_factors") if isinstance(tool_profile.get("risk_factors"), dict) else {}
            for key in aggregate:
                aggregate[key] = aggregate[key] or bool(factors.get(key))
            namespaces.append(
                {
                    "access": context.get("access"),
                    "default_runtime_decision": tool_profile.get("default_runtime_decision"),
                    "namespace": namespace,
                    "purpose": context.get("purpose"),
                    "risk_tier": tool_profile.get("risk_tier"),
                    "suggested_annotations": tool_profile.get("suggested_annotations"),
                    "trusted_server": tool_profile.get("trusted_server"),
                }
            )
        combination = (
            aggregate["reads_private_data"]
            and aggregate["sees_untrusted_content"]
            and aggregate["can_exfiltrate"]
        )
        policy = policies.get(workflow_id, {})
        rows.append(
            {
                "aggregate_risk_factors": aggregate,
                "gateway_policy_hash": stable_hash(policy) if policy else None,
                "lethal_combination_possible": combination,
                "maturity_stage": workflow.get("maturity_stage"),
                "namespaces": namespaces,
                "public_path": workflow.get("public_path"),
                "recommended_session_default": "deny_session_exfiltration_path" if combination else "allow_with_confirmation",
                "status": workflow.get("status"),
                "title": workflow.get("title"),
                "workflow_id": workflow_id,
            }
        )
    return rows


def build_summary(tool_profiles: list[dict[str, Any]], workflow_rows_: list[dict[str, Any]], failures: list[str]) -> dict[str, Any]:
    tier_counts = Counter(str(row.get("risk_tier")) for row in tool_profiles)
    decisions = Counter(str(row.get("default_runtime_decision")) for row in tool_profiles)
    annotation_trust = Counter(str(row.get("annotation_source")) for row in tool_profiles)
    return {
        "annotation_trust_counts": dict(sorted(annotation_trust.items())),
        "default_decision_counts": dict(sorted(decisions.items())),
        "failure_count": len(failures),
        "lethal_combination_workflow_count": sum(1 for row in workflow_rows_ if row.get("lethal_combination_possible")),
        "risk_tier_counts": dict(sorted(tier_counts.items())),
        "tool_profile_count": len(tool_profiles),
        "trusted_server_count": sum(1 for row in tool_profiles if row.get("trusted_server")),
        "workflow_count": len(workflow_rows_),
    }


def build_source_artifacts(repo_root: Path, refs: dict[str, Path]) -> dict[str, dict[str, str]]:
    artifacts: dict[str, dict[str, str]] = {}
    for key, ref in sorted(refs.items()):
        path = resolve(repo_root, ref)
        artifacts[key] = {
            "path": normalize_path(ref),
            "sha256": sha256_file(path),
        }
    return artifacts


def build_pack(
    *,
    profile: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    source_artifacts: dict[str, dict[str, str]],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    auth_by_namespace = authorization_by_namespace(sources["mcp_authorization_conformance_pack"])
    tool_profiles = [
        build_tool_profile(
            connector=connector,
            authorization=auth_by_namespace.get(str(connector.get("namespace"))),
            profile=profile,
        )
        for connector in connector_rows(sources["mcp_connector_trust_pack"])
    ]
    tool_profiles = sorted(tool_profiles, key=lambda row: str(row.get("namespace")))
    workflow_risk = build_workflow_risk_rows(
        manifest=sources["workflow_manifest"],
        gateway_policy=sources["mcp_gateway_policy"],
        tool_profiles=tool_profiles,
    )
    return {
        "control_checks": profile.get("control_checks", []),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "evaluator_contract": {
            "annotation_defaults": profile.get("tool_risk_contract", {}).get("standard_annotation_defaults", {}),
            "default_decision_for_missing_profile": profile.get("tool_risk_contract", {}).get("default_decision"),
            "decision_order": [
                "kill_session_on_tool_risk_signal",
                "deny_scope_drift",
                "deny_annotation_contradiction",
                "deny_session_exfiltration_path",
                "hold_for_tool_risk_review",
                "allow_with_confirmation",
                "allow_tool_call"
            ],
            "session_combination_rule": profile.get("tool_risk_contract", {}).get("session_combination_rule", {}),
        },
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "Tool annotations are not enforcement and can be false on untrusted servers.",
                "treatment": "Use this contract as a policy input, then enforce hard guarantees through gateway scope, sandboxing, authorization, network controls, and output validation."
            },
            {
                "risk": "The risk of a tool depends on the rest of the session, not only on that tool's declaration.",
                "treatment": "Evaluate private-data, untrusted-content, and external-communication factors before each tool call and after tool-list changes."
            },
            {
                "risk": "MCP annotation proposals are still evolving.",
                "treatment": "Version the profile, keep standard annotations conservative, and use namespaced metadata only as deployment-specific evidence until ecosystem-wide annotations stabilize."
            }
        ],
        "risk_tiers": profile.get("risk_tiers", []),
        "schema_version": PACK_SCHEMA_VERSION,
        "selected_feature": {
            "id": "mcp-tool-risk-contract",
            "implementation": [
                "Tool-risk profile under data/assurance.",
                "Deterministic generator under scripts.",
                "Runtime evaluator for annotation, scope, and session-combination decisions.",
                "Generated evidence pack under data/evidence.",
                "Human-readable docs page and MCP tool exposure."
            ],
            "reason": "Enterprise MCP buyers need a way to use tool annotations as risk vocabulary without mistaking them for enforcement, while blocking session-level exfiltration paths before an agent acts."
        },
        "source_artifacts": source_artifacts,
        "standards_alignment": profile.get("standards_alignment", []),
        "tool_profiles": tool_profiles,
        "tool_risk_contract": profile.get("tool_risk_contract", {}),
        "tool_risk_summary": build_summary(tool_profiles, workflow_risk, failures),
        "workflow_tool_risk": workflow_risk,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--connector-trust-pack", type=Path, default=DEFAULT_CONNECTOR_TRUST_PACK)
    parser.add_argument("--authorization-pack", type=Path, default=DEFAULT_AUTHORIZATION_PACK)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--gateway-policy", type=Path, default=DEFAULT_GATEWAY_POLICY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in tool-risk contract is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    refs = {
        "mcp_authorization_conformance_pack": args.authorization_pack,
        "mcp_connector_trust_pack": args.connector_trust_pack,
        "mcp_gateway_policy": args.gateway_policy,
        "mcp_tool_risk_contract_profile": args.profile,
        "workflow_manifest": args.manifest,
    }
    paths = {key: resolve(repo_root, ref) for key, ref in refs.items()}
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(paths["mcp_tool_risk_contract_profile"])
        sources = {
            key: load_json(path)
            for key, path in paths.items()
            if key != "mcp_tool_risk_contract_profile"
        }
        failures = [*validate_profile(profile), *validate_sources(sources)]
        pack = build_pack(
            profile=profile,
            sources=sources,
            source_artifacts=build_source_artifacts(repo_root, refs),
            generated_at=args.generated_at,
            failures=failures,
        )
    except ToolRiskContractError as exc:
        print(f"MCP tool-risk contract generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("MCP tool-risk contract validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_mcp_tool_risk_contract.py", file=sys.stderr)
            return 1
        if current_text != rendered:
            print(f"{output_path} is stale; run scripts/generate_mcp_tool_risk_contract.py", file=sys.stderr)
            return 1
        print(f"Validated MCP tool-risk contract: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated MCP tool-risk contract with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated MCP tool-risk contract: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
