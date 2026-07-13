#!/usr/bin/env python3
"""Generate the SecurityRecipes MCP authorization conformance pack.

This pack sits between the connector trust registry and runtime run
receipts. It answers the enterprise MCP question that connector trust
alone cannot answer: are tokens resource-bound, audience-bound,
short-lived, scoped to the workflow, denied from passthrough, and tied
to consent, session, and audit evidence before the agent can use a tool?
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
DEFAULT_PROFILE = Path("data/assurance/mcp-authorization-conformance-profile.json")
DEFAULT_CONNECTOR_TRUST_PACK = Path("data/evidence/mcp-connector-trust-pack.json")
DEFAULT_CONNECTOR_INTAKE_PACK = Path("data/evidence/mcp-connector-intake-pack.json")
DEFAULT_CONNECTOR_INTAKE_CANDIDATES = Path("data/mcp/connector-intake-candidates.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_OUTPUT = Path("data/evidence/mcp-authorization-conformance-pack.json")

HTTP_TRANSPORTS = {"streamable-http", "http", "sse"}
WRITE_MODES = {"write_branch", "write_ticket"}
APPROVAL_MODES = {"approval_required"}
PROHIBITED_DATA_CLASSES = {
    "private_key",
    "seed_phrase",
    "live_signing_material",
    "raw_access_token",
    "production_credential",
    "registry_publish_credential",
}


class AuthorizationPackError(RuntimeError):
    """Raised when the authorization conformance pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AuthorizationPackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AuthorizationPackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AuthorizationPackError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AuthorizationPackError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthorizationPackError(f"{label} must be an object")
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


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 80, failures, "profile intent must explain product goal")
    standards = as_list(profile.get("standards_alignment"), "profile.standards_alignment")
    require(len(standards) >= 7, failures, "standards_alignment must include current MCP, AI, and security references")
    for idx, standard in enumerate(standards):
        label = f"standards_alignment[{idx}]"
        if not isinstance(standard, dict):
            failures.append(f"{label} must be an object")
            continue
        require(str(standard.get("url", "")).startswith("https://"), failures, f"{label}.url must be https")
        require(len(str(standard.get("coverage", ""))) >= 50, failures, f"{label}.coverage must be specific")

    contract = as_dict(profile.get("conformance_contract"), "profile.conformance_contract")
    require(contract.get("default_decision") == "hold_for_authorization_evidence", failures, "default decision must hold for missing auth evidence")
    require(str(contract.get("canonical_mcp_resource_uri", "")).startswith("https://"), failures, "canonical MCP resource URI must be https")
    require(len(as_list(contract.get("required_runtime_attributes"), "required_runtime_attributes")) >= 12, failures, "runtime attributes must include token, session, and workflow evidence")
    require(len(as_list(profile.get("control_checks"), "profile.control_checks")) >= 12, failures, "control_checks must cover resource, token, client metadata, scope challenge, step-up, session, and audit controls")
    return failures


def validate_sources(
    connector_trust_pack: dict[str, Any],
    connector_intake_pack: dict[str, Any],
    connector_intake_candidates: dict[str, Any],
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    require(connector_trust_pack.get("schema_version") == "1.0", failures, "connector trust pack schema_version must be 1.0")
    require(connector_intake_pack.get("schema_version") == "1.0", failures, "connector intake pack schema_version must be 1.0")
    require(connector_intake_candidates.get("schema_version") == "1.0", failures, "connector intake candidates schema_version must be 1.0")
    require(manifest.get("schema_version") == "1.0", failures, "workflow manifest schema_version must be 1.0")
    require(policy_pack.get("schema_version") == "1.0", failures, "gateway policy schema_version must be 1.0")
    require(not connector_trust_pack.get("failures"), failures, "connector trust pack must have zero failures")
    require(not connector_intake_pack.get("failures"), failures, "connector intake pack must have zero failures")
    return failures


def canonical_resource_uri(profile: dict[str, Any]) -> str:
    return str(profile.get("conformance_contract", {}).get("canonical_mcp_resource_uri"))


def registered_control_gaps(connector: dict[str, Any], profile: dict[str, Any]) -> list[str]:
    trust_tier = connector.get("trust_tier", {})
    tier_id = str(trust_tier.get("id") if isinstance(trust_tier, dict) else trust_tier)
    if tier_id == "tier_0_public_context":
        return []
    controls = {str(control) for control in connector.get("required_controls", []) or []}
    contract = profile.get("conformance_contract", {})
    gaps = [
        control
        for control in contract.get("gateway_attestation_controls", [])
        if str(control) not in controls
    ]
    modes = {str(mode) for mode in connector.get("access_modes", []) or []}
    if modes & WRITE_MODES:
        gaps.extend(
            control
            for control in contract.get("write_attestation_controls", [])
            if str(control) not in controls
        )
    if modes & APPROVAL_MODES:
        gaps.extend(
            control
            for control in contract.get("approval_attestation_controls", [])
            if str(control) not in controls
        )
    return sorted(set(gaps))


def metadata_required(connector: dict[str, Any], profile: dict[str, Any]) -> list[str]:
    if str(connector.get("transport")) not in HTTP_TRANSPORTS:
        return []
    return list(profile.get("conformance_contract", {}).get("live_metadata_evidence_required", []))


def registered_decision(connector: dict[str, Any], gaps: list[str]) -> str:
    trust_tier = connector.get("trust_tier", {})
    tier_id = str(trust_tier.get("id") if isinstance(trust_tier, dict) else trust_tier)
    data_classes = {str(item) for item in connector.get("data_classes", []) or []}
    if data_classes & PROHIBITED_DATA_CLASSES or tier_id == "tier_4_prohibited":
        return "deny_until_redesigned"
    if tier_id == "tier_0_public_context":
        return "approve_public_context_no_auth"
    if gaps:
        return "hold_for_authorization_evidence"
    return "approve_with_gateway_attestation"


def registered_rows(connector_trust_pack: dict[str, Any], profile: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for connector in as_list(connector_trust_pack.get("connectors"), "connector_trust_pack.connectors"):
        if not isinstance(connector, dict):
            continue
        gaps = registered_control_gaps(connector, profile)
        metadata = metadata_required(connector, profile)
        rows.append(
            {
                "access_modes": connector.get("access_modes", []),
                "canonical_resource_uri": canonical_resource_uri(profile),
                "conformance_decision": registered_decision(connector, gaps),
                "connector_id": connector.get("connector_id") or connector.get("id"),
                "control_gaps": gaps,
                "data_classes": connector.get("data_classes", []),
                "evidence_mode": "gateway_control_attestation",
                "latest_spec_controls": [
                    "protected_resource_metadata_discovery",
                    "client_id_metadata_document",
                    "scope_challenge_handling",
                    "step_up_authorization"
                ],
                "metadata_evidence_required": metadata,
                "namespace": connector.get("namespace"),
                "owner": connector.get("owner"),
                "required_runtime_attributes": profile.get("conformance_contract", {}).get("required_runtime_attributes", []),
                "status": connector.get("status"),
                "title": connector.get("title"),
                "transport": connector.get("transport"),
                "trust_tier": connector.get("trust_tier"),
            }
        )
    return sorted(rows, key=lambda row: str(row.get("namespace")))


def candidate_control_gaps(candidate: dict[str, Any], profile: dict[str, Any]) -> list[str]:
    declared = {str(control) for control in candidate.get("declared_controls", []) or []}
    auth = candidate.get("auth") if isinstance(candidate.get("auth"), dict) else {}
    network = candidate.get("network") if isinstance(candidate.get("network"), dict) else {}
    gaps = []
    if str(candidate.get("transport")) in HTTP_TRANSPORTS:
        if not auth.get("resource_indicators"):
            gaps.append("resource_indicators")
        if not auth.get("audience_validation"):
            gaps.append("audience_validation")
        if not auth.get("client_id_metadata_document"):
            gaps.append("client_id_metadata_document")
        if not auth.get("scope_challenge_handling"):
            gaps.append("scope_challenge_handling")
        if not auth.get("pkce"):
            gaps.append("pkce")
        if not auth.get("short_lived_tokens"):
            gaps.append("short_lived_tokens")
    access_modes = {
        str(mode)
        for mode in candidate.get("requested_access_modes", []) or candidate.get("access_modes", []) or []
    }
    if "approval_required" in access_modes and not auth.get("step_up_authorization"):
        gaps.append("step_up_authorization")
    if auth.get("token_passthrough"):
        gaps.append("deny_token_passthrough")
    if network.get("allows_private_network") or network.get("allows_metadata_ip"):
        gaps.append("deny_private_network_egress")
    for control in ["session_binding", "audit_every_tool_call"]:
        if control not in declared:
            gaps.append(control)
    if str(candidate.get("transport")) == "stdio" and not auth.get("command_allowlist"):
        gaps.append("stdio_command_allowlist")
    return sorted(set(gaps))


def candidate_decision(candidate: dict[str, Any], gaps: list[str]) -> str:
    data_classes = {str(item) for item in candidate.get("data_classes", []) or []}
    auth = candidate.get("auth") if isinstance(candidate.get("auth"), dict) else {}
    if data_classes & PROHIBITED_DATA_CLASSES:
        return "deny_until_redesigned"
    if auth.get("token_passthrough"):
        return "deny_until_redesigned"
    if gaps:
        return "hold_for_authorization_evidence"
    return "approve_for_pilot"


def candidate_rows(
    connector_intake_pack: dict[str, Any],
    connector_intake_candidates: dict[str, Any],
    profile: dict[str, Any],
) -> list[dict[str, Any]]:
    rows = []
    raw_candidates = {
        str(candidate.get("id")): candidate
        for candidate in connector_intake_candidates.get("candidates", [])
        if isinstance(candidate, dict) and candidate.get("id")
    }
    for candidate in as_list(connector_intake_pack.get("candidate_evaluations"), "connector_intake_pack.candidate_evaluations"):
        if not isinstance(candidate, dict):
            continue
        registry_preview = candidate.get("registry_patch_preview") if isinstance(candidate.get("registry_patch_preview"), dict) else {}
        raw_candidate = raw_candidates.get(str(candidate.get("candidate_id")), {})
        candidate_profile = {**candidate, **raw_candidate, **registry_preview}
        gaps = sorted(set(candidate.get("control_gaps", []) or []) | set(candidate_control_gaps(candidate_profile, profile)))
        rows.append(
            {
                "access_modes": candidate.get("requested_access_modes", registry_preview.get("access_modes", [])),
                "candidate_id": candidate.get("candidate_id"),
                "canonical_resource_uri": f"{canonical_resource_uri(profile)}#{candidate.get('namespace')}",
                "conformance_decision": candidate_decision(candidate_profile, gaps),
                "control_gaps": gaps,
                "data_classes": registry_preview.get("data_classes", []),
                "evidence_mode": "candidate_auth_profile",
                "latest_spec_controls": [
                    "protected_resource_metadata_discovery",
                    "client_id_metadata_document",
                    "scope_challenge_handling",
                    "step_up_authorization"
                ],
                "intake_decision": candidate.get("intake_decision"),
                "namespace": candidate.get("namespace"),
                "requested_access_modes": candidate.get("requested_access_modes", []),
                "risk_score": candidate.get("risk_score"),
                "source": candidate.get("source", {}),
                "title": candidate.get("title"),
                "transport": candidate.get("transport"),
            }
        )
    return sorted(rows, key=lambda row: (-int(row.get("risk_score") or 0), str(row.get("candidate_id"))))


def workflow_policy_hash(policy: dict[str, Any]) -> str:
    text = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def policy_by_workflow(policy_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(policy.get("workflow_id")): policy
        for policy in as_list(policy_pack.get("workflow_policies"), "policy_pack.workflow_policies")
        if isinstance(policy, dict) and policy.get("workflow_id")
    }


def workflow_authorization_map(
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    registered: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_namespace = {str(row.get("namespace")): row for row in registered}
    policies = policy_by_workflow(policy_pack)
    rows = []
    for workflow in as_list(manifest.get("workflows"), "manifest.workflows"):
        if not isinstance(workflow, dict):
            continue
        workflow_id = str(workflow.get("id"))
        policy = policies.get(workflow_id, {})
        namespaces = []
        for context in workflow.get("mcp_context", []) or []:
            if not isinstance(context, dict):
                continue
            namespace = str(context.get("namespace"))
            profile = by_namespace.get(namespace, {})
            namespaces.append(
                {
                    "access": context.get("access"),
                    "authorization_decision": profile.get("conformance_decision"),
                    "canonical_resource_uri": profile.get("canonical_resource_uri"),
                    "connector_id": profile.get("connector_id"),
                    "namespace": namespace,
                    "purpose": context.get("purpose"),
                    "transport": profile.get("transport"),
                }
            )
        rows.append(
            {
                "authorization_policy_hash": workflow_policy_hash(policy),
                "maturity_stage": workflow.get("maturity_stage"),
                "namespaces": namespaces,
                "public_path": workflow.get("public_path"),
                "status": workflow.get("status"),
                "title": workflow.get("title"),
                "workflow_id": workflow_id,
            }
        )
    return rows


def build_summary(
    registered: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    failures: list[str],
) -> dict[str, Any]:
    registered_counts = Counter(str(row.get("conformance_decision")) for row in registered)
    candidate_counts = Counter(str(row.get("conformance_decision")) for row in candidates)
    return {
        "candidate_count": len(candidates),
        "candidate_decision_counts": dict(sorted(candidate_counts.items())),
        "client_metadata_evidence_required_count": sum(
            1
            for row in registered
            if "client_metadata_document_url" in (row.get("metadata_evidence_required") or [])
        ),
        "connector_count": len(registered),
        "failure_count": len(failures),
        "metadata_evidence_required_count": sum(1 for row in registered if row.get("metadata_evidence_required")),
        "registered_decision_counts": dict(sorted(registered_counts.items())),
        "step_up_connector_count": sum(
            1
            for row in registered
            if "approval_required" in {str(mode) for mode in row.get("access_modes", []) or []}
        ),
        "workflow_count": len(workflows),
    }


def build_pack(
    *,
    profile: dict[str, Any],
    connector_trust_pack: dict[str, Any],
    connector_intake_pack: dict[str, Any],
    connector_intake_candidates: dict[str, Any],
    manifest: dict[str, Any],
    policy_pack: dict[str, Any],
    source_paths: dict[str, Path],
    source_refs: dict[str, Path],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    registered = registered_rows(connector_trust_pack, profile)
    candidates = candidate_rows(connector_intake_pack, connector_intake_candidates, profile)
    workflow_rows = workflow_authorization_map(manifest, policy_pack, registered)
    return {
        "authorization_contract": profile.get("conformance_contract", {}),
        "authorization_pack_id": "security-recipes-mcp-authorization-conformance",
        "authorization_summary": build_summary(registered, candidates, workflow_rows, failures),
        "candidate_authorization": candidates,
        "control_checks": profile.get("control_checks", []),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "registered_connector_authorization": registered,
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": {
            key: {
                "path": normalize_path(source_refs[key]),
                "sha256": sha256_file(source_paths[key]),
            }
            for key in sorted(source_paths)
        },
        "standards_alignment": profile.get("standards_alignment", []),
        "workflow_authorization_map": workflow_rows,
    }


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--connector-trust-pack", type=Path, default=DEFAULT_CONNECTOR_TRUST_PACK)
    parser.add_argument("--connector-intake-pack", type=Path, default=DEFAULT_CONNECTOR_INTAKE_PACK)
    parser.add_argument("--connector-intake-candidates", type=Path, default=DEFAULT_CONNECTOR_INTAKE_CANDIDATES)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in authorization pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    paths = {
        "mcp_authorization_conformance_profile": resolve(repo_root, args.profile),
        "mcp_connector_intake_candidates": resolve(repo_root, args.connector_intake_candidates),
        "mcp_connector_intake_pack": resolve(repo_root, args.connector_intake_pack),
        "mcp_connector_trust_pack": resolve(repo_root, args.connector_trust_pack),
        "mcp_gateway_policy": resolve(repo_root, args.policy),
        "workflow_manifest": resolve(repo_root, args.manifest),
    }
    refs = {
        "mcp_authorization_conformance_profile": args.profile,
        "mcp_connector_intake_candidates": args.connector_intake_candidates,
        "mcp_connector_intake_pack": args.connector_intake_pack,
        "mcp_connector_trust_pack": args.connector_trust_pack,
        "mcp_gateway_policy": args.policy,
        "workflow_manifest": args.manifest,
    }
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(paths["mcp_authorization_conformance_profile"])
        connector_intake_candidates = load_json(paths["mcp_connector_intake_candidates"])
        connector_trust_pack = load_json(paths["mcp_connector_trust_pack"])
        connector_intake_pack = load_json(paths["mcp_connector_intake_pack"])
        manifest = load_json(paths["workflow_manifest"])
        policy_pack = load_json(paths["mcp_gateway_policy"])
        failures = validate_profile(profile)
        failures.extend(validate_sources(connector_trust_pack, connector_intake_pack, connector_intake_candidates, manifest, policy_pack))
        pack = build_pack(
            profile=profile,
            connector_trust_pack=connector_trust_pack,
            connector_intake_pack=connector_intake_pack,
            connector_intake_candidates=connector_intake_candidates,
            manifest=manifest,
            policy_pack=policy_pack,
            source_paths=paths,
            source_refs=refs,
            generated_at=args.generated_at,
            failures=failures,
        )
    except AuthorizationPackError as exc:
        print(f"MCP authorization conformance pack generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)
    if args.check:
        if failures:
            print("MCP authorization conformance pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_mcp_authorization_conformance_pack.py", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(f"{output_path} is stale; run scripts/generate_mcp_authorization_conformance_pack.py", file=sys.stderr)
            return 1
        print(f"Validated MCP authorization conformance pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")
    if failures:
        print("Generated MCP authorization conformance pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated MCP authorization conformance pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
