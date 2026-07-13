#!/usr/bin/env python3
"""Generate the SecurityRecipes Agent Trust Fabric pack.

The pack composes generated identity, authorization, context, egress,
telemetry, action-runtime, receipt, freshness, hosted MCP, and trust-center
evidence into one MCP-readable zero-trust decision surface for agents.
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
DEFAULT_PROFILE = Path("data/assurance/agent-trust-fabric-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/agent-trust-fabric-pack.json")

SOURCE_REFS = {
    "workflow_manifest": Path("data/control-plane/workflow-manifests.json"),
    "agent_identity_ledger": Path("data/evidence/agent-identity-delegation-ledger.json"),
    "agentic_entitlement_review_pack": Path("data/evidence/agentic-entitlement-review-pack.json"),
    "mcp_authorization_conformance": Path("data/evidence/mcp-authorization-conformance-pack.json"),
    "secure_context_trust_pack": Path("data/evidence/secure-context-trust-pack.json"),
    "context_poisoning_guard_pack": Path("data/evidence/context-poisoning-guard-pack.json"),
    "context_egress_boundary_pack": Path("data/evidence/context-egress-boundary-pack.json"),
    "agentic_action_runtime_pack": Path("data/evidence/agentic-action-runtime-pack.json"),
    "agentic_telemetry_contract": Path("data/evidence/agentic-telemetry-contract.json"),
    "agentic_soc_detection_pack": Path("data/evidence/agentic-soc-detection-pack.json"),
    "agentic_run_receipt_pack": Path("data/evidence/agentic-run-receipt-pack.json"),
    "agentic_source_freshness_watch": Path("data/evidence/agentic-source-freshness-watch.json"),
    "hosted_mcp_readiness_pack": Path("data/evidence/hosted-mcp-readiness-pack.json"),
    "enterprise_trust_center_export": Path("data/evidence/enterprise-trust-center-export.json"),
}


class AgentTrustFabricPackError(RuntimeError):
    """Raised when the trust fabric pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AgentTrustFabricPackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise AgentTrustFabricPackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AgentTrustFabricPackError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentTrustFabricPackError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AgentTrustFabricPackError(f"{label} must be a list")
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


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must explain the trust fabric goal")

    source_refs = as_list(profile.get("source_references"), "source_references")
    require(len(source_refs) >= 8, failures, "source_references must include current AI agent, MCP, guardrail, and telemetry sources")
    for idx, source in enumerate(source_refs):
        item = as_dict(source, f"source_references[{idx}]")
        source_id = str(item.get("id", "")).strip()
        require(bool(source_id), failures, f"source_references[{idx}].id is required")
        require(str(item.get("url", "")).startswith("https://"), failures, f"{source_id}: url must be https")
        require(str(item.get("publisher", "")).strip(), failures, f"{source_id}: publisher is required")
        require(str(item.get("published", "")).strip(), failures, f"{source_id}: published is required")
        require(len(str(item.get("why_it_matters", ""))) >= 60, failures, f"{source_id}: why_it_matters must be specific")

    contract = as_dict(profile.get("trust_contract"), "trust_contract")
    require(
        contract.get("default_state")
        == "agent_untrusted_until_identity_context_scope_behavior_telemetry_and_containment_evidence_are_bound",
        failures,
        "trust_contract.default_state must fail closed",
    )
    required_sources = {str(item) for item in as_list(contract.get("required_evidence_sources"), "trust_contract.required_evidence_sources")}
    require(len(required_sources) >= int(contract.get("minimum_evidence_sources") or 0), failures, "required evidence source count below minimum")
    require(not sorted(required_sources - set(SOURCE_REFS)), failures, "trust_contract contains unknown evidence sources")
    require(
        len(as_list(contract.get("required_runtime_fields"), "trust_contract.required_runtime_fields"))
        >= int(contract.get("minimum_runtime_fields") or 0),
        failures,
        "runtime field count below minimum",
    )

    dimensions = as_list(profile.get("trust_dimensions"), "trust_dimensions")
    require(len(dimensions) >= int(contract.get("minimum_dimensions") or 0), failures, "trust dimension count below minimum")
    dimension_ids: set[str] = set()
    weight_total = 0
    for idx, dimension in enumerate(dimensions):
        item = as_dict(dimension, f"trust_dimensions[{idx}]")
        dimension_id = str(item.get("id", "")).strip()
        require(bool(dimension_id), failures, f"trust_dimensions[{idx}].id is required")
        require(dimension_id not in dimension_ids, failures, f"{dimension_id}: duplicate dimension id")
        dimension_ids.add(dimension_id)
        weight = int(item.get("weight") or 0)
        weight_total += weight
        require(weight > 0, failures, f"{dimension_id}: weight must be positive")
        evidence = {str(row) for row in as_list(item.get("required_evidence"), f"{dimension_id}.required_evidence")}
        require(bool(evidence), failures, f"{dimension_id}: required_evidence is required")
        require(not sorted(evidence - set(SOURCE_REFS)), failures, f"{dimension_id}: unknown evidence sources")
        require(len(as_list(item.get("mcp_tools"), f"{dimension_id}.mcp_tools")) >= 3, failures, f"{dimension_id}: MCP tools are required")
        require(len(as_list(item.get("failure_modes"), f"{dimension_id}.failure_modes")) >= 3, failures, f"{dimension_id}: failure modes are required")
    require(weight_total == 100, failures, "trust dimension weights must total 100")

    tiers = as_list(profile.get("trust_tiers"), "trust_tiers")
    require(len(tiers) >= 4, failures, "trust_tiers must include at least four maturity levels")
    for idx, tier in enumerate(tiers):
        item = as_dict(tier, f"trust_tiers[{idx}]")
        require(str(item.get("id", "")).strip(), failures, f"trust_tiers[{idx}].id is required")
        require(int(item.get("minimum_score") or 0) > 0, failures, f"{item.get('id')}: minimum_score is required")
        require(len(as_list(item.get("allowed_actions"), f"{item.get('id')}.allowed_actions")) >= 2, failures, f"{item.get('id')}: allowed_actions are required")

    return failures


def load_sources(repo_root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    payloads: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for source_id, ref in SOURCE_REFS.items():
        try:
            payloads[source_id] = load_json(resolve(repo_root, ref))
        except AgentTrustFabricPackError as exc:
            failures.append(f"{source_id}: {exc}")
    return payloads, failures


def validate_sources(payloads: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    missing = sorted(set(SOURCE_REFS) - set(payloads))
    require(not missing, failures, f"missing source payloads: {missing}")
    for source_id, payload in payloads.items():
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


def active_workflows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        workflow
        for workflow in manifest.get("workflows", [])
        if isinstance(workflow, dict) and str(workflow.get("status", "")).lower() == "active"
    ]


def workflow_namespaces(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in workflow.get("mcp_context", []) if isinstance(row, dict)]


def workflow_risk_flags(workflow: dict[str, Any]) -> set[str]:
    namespaces = workflow_namespaces(workflow)
    namespace_signal = " ".join(
        " ".join(str(namespace.get(key, "")) for key in ("namespace", "access", "purpose"))
        for namespace in namespaces
    ).lower()
    title_signal = " ".join(
        [
            str(workflow.get("id", "")),
            str(workflow.get("title", "")),
        ]
    ).lower()
    kill_signal = " ".join(str(item) for item in workflow.get("kill_signals", []) if item).lower()
    flags: set[str] = set()
    if any(str(namespace.get("access")) == "write_branch" for namespace in namespaces):
        flags.add("scoped_write")
    if any(term in f"{namespace_signal} {title_signal}" for term in ["secret", "sensitive", "credential", "token", "sde"]):
        flags.add("sensitive_data")
    if (
        "approval_required" in namespace_signal
        or any(term in namespace_signal for term in ["quarantine", "purge", "payment", "chain", "governance"])
        or any(term in kill_signal for term in ["direct purge", "production payment", "governance proposal", "bridge write", "deployer"])
    ):
        flags.add("high_impact_action")
    if any(term in f"{namespace_signal} {title_signal}" for term in ["crypto", "defi", "wallet", "payment", "funds", "chain."]):
        flags.add("irreversible_transaction")
    if len(namespaces) >= 3:
        flags.add("multi_namespace")
    return flags


def workflow_floor(flags: set[str]) -> str:
    if "irreversible_transaction" in flags or "high_impact_action" in flags:
        return "principal"
    if "scoped_write" in flags or "sensitive_data" in flags or "multi_namespace" in flags:
        return "operator"
    return "apprentice"


def workflow_trust_matrix(manifest: dict[str, Any], profile: dict[str, Any]) -> list[dict[str, Any]]:
    dimensions = profile.get("trust_dimensions", [])
    rows: list[dict[str, Any]] = []
    for workflow in active_workflows(manifest):
        flags = workflow_risk_flags(workflow)
        rows.append(
            {
                "default_trust_tier": workflow_floor(flags),
                "maturity_stage": workflow.get("maturity_stage"),
                "mcp_namespaces": [
                    {
                        "access": namespace.get("access"),
                        "namespace": namespace.get("namespace"),
                    }
                    for namespace in workflow_namespaces(workflow)
                ],
                "required_dimension_ids": [dimension.get("id") for dimension in dimensions],
                "risk_flags": sorted(flags),
                "title": workflow.get("title"),
                "workflow_id": workflow.get("id"),
            }
        )
    return rows


def trust_dimension_rows(profile: dict[str, Any], source_artifacts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for dimension in profile.get("trust_dimensions", []):
        evidence = [str(item) for item in dimension.get("required_evidence", [])]
        rows.append(
            {
                "evidence_paths": [
                    source_artifacts[source_id]["path"]
                    for source_id in evidence
                    if source_id in source_artifacts
                ],
                "failure_modes": dimension.get("failure_modes", []),
                "id": dimension.get("id"),
                "mcp_tools": dimension.get("mcp_tools", []),
                "question": dimension.get("question"),
                "required_evidence": evidence,
                "title": dimension.get("title"),
                "weight": dimension.get("weight"),
            }
        )
    return rows


def tabletop_cases() -> list[dict[str, Any]]:
    return [
        {
            "expected_decision": "allow_trusted_agent_context",
            "id": "trusted-scoped-remediation-run",
            "trigger": "A scoped dependency remediation run has identity, context, authorization, egress, telemetry, receipt, and source freshness evidence."
        },
        {
            "expected_decision": "hold_for_step_up",
            "id": "operator-tier-without-approval",
            "trigger": "An agent requests operator autonomy for a scoped write while approval or action-runtime evidence is incomplete."
        },
        {
            "expected_decision": "deny_untrusted_agent",
            "id": "unknown-workflow-or-stale-source",
            "trigger": "The workflow is missing from the generated matrix or source freshness is stale enough to drop the score below the deny threshold."
        },
        {
            "expected_decision": "kill_session_on_agent_trust_break",
            "id": "token-passthrough-or-secret-egress",
            "trigger": "A protected MCP token is passed downstream, a revoked identity is used, or a secret crosses an external egress boundary."
        }
    ]


def build_summary(
    dimensions: list[dict[str, Any]],
    matrix: list[dict[str, Any]],
    source_artifacts: dict[str, dict[str, Any]],
    failures: list[str],
) -> dict[str, Any]:
    floor_counts = Counter(str(row.get("default_trust_tier")) for row in matrix)
    source_failure_count = sum(int(row.get("failure_count") or 0) for row in source_artifacts.values())
    return {
        "dimension_count": len(dimensions),
        "failure_count": len(failures),
        "source_failure_count": source_failure_count,
        "source_pack_count": len(source_artifacts),
        "status": "agent_trust_fabric_ready" if not failures else "needs_trust_fabric_review",
        "trust_tier_counts": dict(sorted(floor_counts.items())),
        "workflow_count": len(matrix),
    }


def build_pack(
    *,
    profile: dict[str, Any],
    payloads: dict[str, dict[str, Any]],
    source_artifacts: dict[str, dict[str, Any]],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    dimensions = trust_dimension_rows(profile, source_artifacts)
    matrix = workflow_trust_matrix(payloads["workflow_manifest"], profile)
    return {
        "agent_trust_fabric_pack_id": "security-recipes.agent-trust-fabric.v1",
        "commercialization_path": profile.get("commercialization_path", {}),
        "enterprise_adoption_packet": {
            "board_level_claim": profile.get("executive_readout", {}).get("board_level_claim"),
            "default_questions_answered": [
                "Which agent is asking for context or tool access?",
                "Which workflow and trust tier does the run belong to?",
                "Which evidence proves identity, context, scope, behavior, egress, and containment?",
                "Should the runtime allow, hold, deny, or kill the run?",
                "Which source packs and MCP tools explain the decision?"
            ],
            "recommended_first_use": profile.get("executive_readout", {}).get("recommended_first_use"),
            "sales_motion": "Lead with the open trust-fabric pack, then sell hosted customer-specific trust scoring, policy adapters, signed verdicts, SOC export, and trust-center evidence APIs."
        },
        "executive_readout": profile.get("executive_readout", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "positioning": profile.get("positioning", {}),
        "runtime_policy": profile.get("runtime_policy", {}),
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": source_artifacts,
        "source_references": profile.get("source_references", []),
        "tabletop_cases": tabletop_cases(),
        "trust_contract": profile.get("trust_contract", {}),
        "trust_dimensions": dimensions,
        "trust_fabric_summary": build_summary(dimensions, matrix, source_artifacts, failures),
        "trust_tiers": profile.get("trust_tiers", []),
        "workflow_trust_matrix": matrix,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in Agent Trust Fabric pack is stale.")
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
    except AgentTrustFabricPackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = stable_json(pack)
    if args.check:
        if not output_path.exists():
            print(f"{output_path} is missing; run scripts/generate_agent_trust_fabric_pack.py", file=sys.stderr)
            return 1
        current = output_path.read_text(encoding="utf-8")
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_agent_trust_fabric_pack.py", file=sys.stderr)
            return 1
        if failures:
            print("agent trust fabric pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print(f"generated {output_path} with {len(failures)} validation failure(s)", file=sys.stderr)
        return 1
    print(f"generated {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
