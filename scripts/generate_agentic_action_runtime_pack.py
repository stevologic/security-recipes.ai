#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic action runtime pack.

The pack is the runtime action layer for the secure context thesis. It
converts the generated context, identity, MCP authorization, egress,
handoff, receipt, incident, telemetry, and catastrophic-risk evidence
into action envelopes that an agent host or MCP gateway can evaluate
before an autonomous side effect is allowed to execute.
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
DEFAULT_PROFILE = Path("data/assurance/agentic-action-runtime-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-action-runtime-pack.json")

SOURCE_REFS = {
    "a2a_agent_card_trust_profile": Path("data/evidence/a2a-agent-card-trust-profile.json"),
    "agent_capability_risk_register": Path("data/evidence/agent-capability-risk-register.json"),
    "agent_handoff_boundary_pack": Path("data/evidence/agent-handoff-boundary-pack.json"),
    "agent_identity_ledger": Path("data/evidence/agent-identity-delegation-ledger.json"),
    "agent_memory_boundary_pack": Path("data/evidence/agent-memory-boundary-pack.json"),
    "agent_skill_supply_chain_pack": Path("data/evidence/agent-skill-supply-chain-pack.json"),
    "agentic_catastrophic_risk_annex": Path("data/evidence/agentic-catastrophic-risk-annex.json"),
    "agentic_incident_response_pack": Path("data/evidence/agentic-incident-response-pack.json"),
    "agentic_run_receipt_pack": Path("data/evidence/agentic-run-receipt-pack.json"),
    "agentic_telemetry_contract": Path("data/evidence/agentic-telemetry-contract.json"),
    "context_egress_boundary_pack": Path("data/evidence/context-egress-boundary-pack.json"),
    "context_poisoning_guard_pack": Path("data/evidence/context-poisoning-guard-pack.json"),
    "mcp_authorization_conformance": Path("data/evidence/mcp-authorization-conformance-pack.json"),
    "mcp_connector_intake_pack": Path("data/evidence/mcp-connector-intake-pack.json"),
    "mcp_gateway_policy": Path("data/policy/mcp-gateway-policy.json"),
    "mcp_stdio_launch_boundary_pack": Path("data/evidence/mcp-stdio-launch-boundary-pack.json"),
    "secure_context_trust_pack": Path("data/evidence/secure-context-trust-pack.json"),
    "workflow_manifest": Path("data/control-plane/workflow-manifests.json"),
}

EVIDENCE_ID_TO_SOURCE = dict(SOURCE_REFS)


class ActionRuntimePackError(RuntimeError):
    """Raised when the action runtime pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ActionRuntimePackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ActionRuntimePackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ActionRuntimePackError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ActionRuntimePackError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ActionRuntimePackError(f"{label} must be a list")
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
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must describe the action runtime goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 6, failures, "standards_alignment must include CSA, OWASP, MCP, NIST, and CISA references")
    seen_standards: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in seen_standards, failures, f"{standard_id}: duplicate standard id")
        seen_standards.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 60, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("action_contract"), "action_contract")
    require(
        contract.get("default_state")
        == "action_untrusted_until_context_policy_intent_behavior_identity_and_receipt_evidence_are_bound",
        failures,
        "action_contract.default_state must fail closed",
    )
    required_sources = {str(item) for item in as_list(contract.get("required_evidence_sources"), "action_contract.required_evidence_sources")}
    require(len(required_sources) >= int(contract.get("minimum_required_evidence_sources") or 0), failures, "required evidence source count below minimum")
    require(not sorted(required_sources - set(EVIDENCE_ID_TO_SOURCE)), failures, "action_contract contains unknown evidence sources")
    require(
        len(as_list(contract.get("required_runtime_fields"), "action_contract.required_runtime_fields")) >= 16,
        failures,
        "runtime fields must bind workflow, run, identity, context, policy, authorization, receipts, approvals, and kill signals",
    )

    action_classes = as_list(profile.get("action_classes"), "action_classes")
    require(len(action_classes) >= int(contract.get("minimum_action_classes") or 0), failures, "action class count below minimum")
    seen_actions: set[str] = set()
    for idx, action_class in enumerate(action_classes):
        item = as_dict(action_class, f"action_classes[{idx}]")
        action_id = str(item.get("id", "")).strip()
        require(bool(action_id), failures, f"action_classes[{idx}].id is required")
        require(action_id not in seen_actions, failures, f"{action_id}: duplicate action id")
        seen_actions.add(action_id)
        require(str(item.get("risk_tier")) in {"low", "medium", "high", "critical"}, failures, f"{action_id}: risk_tier must be low, medium, high, or critical")
        require(str(item.get("default_decision", "")).strip(), failures, f"{action_id}: default_decision is required")
        require(len(as_list(item.get("required_evidence"), f"{action_id}.required_evidence")) >= 5, failures, f"{action_id}: required evidence is incomplete")
        require(len(as_list(item.get("hold_conditions"), f"{action_id}.hold_conditions")) >= 2, failures, f"{action_id}: hold conditions are incomplete")
        require(len(as_list(item.get("kill_signals"), f"{action_id}.kill_signals")) >= 2, failures, f"{action_id}: kill signals are incomplete")
        linked = {str(evidence) for evidence in as_list(item.get("linked_evidence"), f"{action_id}.linked_evidence")}
        require(not sorted(linked - set(EVIDENCE_ID_TO_SOURCE)), failures, f"{action_id}: unknown linked evidence")
        require(len(as_list(item.get("mcp_tools"), f"{action_id}.mcp_tools")) >= 3, failures, f"{action_id}: MCP tools are required")

    return failures


def load_sources(repo_root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    payloads: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for source_id, ref in SOURCE_REFS.items():
        path = resolve(repo_root, ref)
        try:
            payloads[source_id] = load_json(path)
        except ActionRuntimePackError as exc:
            failures.append(f"{source_id}: {exc}")
    return payloads, failures


def validate_sources(payloads: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    missing = sorted(set(SOURCE_REFS) - set(payloads))
    require(not missing, failures, f"missing source payloads: {missing}")
    for source_id, payload in payloads.items():
        require(payload.get("schema_version") == "1.0", failures, f"{source_id} schema_version must be 1.0")
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


def workflow_signal_text(workflow: dict[str, Any]) -> str:
    parts: list[str] = [
        str(workflow.get("id", "")),
        str(workflow.get("title", "")),
        " ".join(str(item) for item in workflow.get("kill_signals", []) if item),
    ]
    for namespace in workflow_namespaces(workflow):
        parts.extend([
            str(namespace.get("namespace", "")),
            str(namespace.get("access", "")),
            str(namespace.get("purpose", "")),
        ])
    scope = workflow.get("scope")
    if isinstance(scope, dict):
        parts.extend(str(item) for item in scope.get("allowed_paths", []) if item)
        parts.extend(str(item) for item in scope.get("forbidden_paths", []) if item)
    return " ".join(parts).lower()


def action_ids_for_workflow(workflow: dict[str, Any]) -> list[str]:
    signal = workflow_signal_text(workflow)
    namespaces = workflow_namespaces(workflow)
    actions = {"external_context_egress"}

    if any(str(namespace.get("access")) == "write_branch" for namespace in namespaces):
        actions.add("repo_branch_write")
    if "approval_required" in signal or "registries.quarantine" in signal or "inventory.artifacts" in signal:
        actions.add("artifact_or_registry_quarantine")
    if any(term in signal for term in ["crypto", "defi", "payment", "wallet", "funds", "chain.", "protocol."]):
        actions.add("funds_or_irreversible_transaction")
    if any(term in signal for term in ["secret", "sensitive", "credential", "token", "sde"]):
        actions.add("credential_or_secret_access")
    if any(term in signal for term in ["memory", "replay", "receipt"]):
        actions.add("persistent_memory_write")
    if any(term in signal for term in ["skill", "hook", "agent rules", "rules file", "stdio"]):
        actions.add("skill_or_tool_install")

    return sorted(actions)


def action_class_rows(profile: dict[str, Any], source_artifacts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for action_class in profile["action_classes"]:
        linked = [str(item) for item in action_class.get("linked_evidence", [])]
        rows.append(
            {
                "default_decision": action_class.get("default_decision"),
                "evidence_paths": [
                    source_artifacts[source_id]["path"]
                    for source_id in linked
                    if source_id in source_artifacts
                ],
                "hold_conditions": action_class.get("hold_conditions", []),
                "id": action_class.get("id"),
                "kill_signals": action_class.get("kill_signals", []),
                "linked_evidence": linked,
                "mcp_tools": action_class.get("mcp_tools", []),
                "required_evidence": action_class.get("required_evidence", []),
                "risk_tier": action_class.get("risk_tier"),
                "title": action_class.get("title"),
            }
        )
    return rows


def action_decision_floor(action_ids: list[str], action_by_id: dict[str, dict[str, Any]]) -> str:
    risk_tiers = {str(action_by_id[action_id].get("risk_tier")) for action_id in action_ids if action_id in action_by_id}
    if "critical" in risk_tiers:
        return "deny_unapproved_high_impact_action"
    if "high" in risk_tiers:
        return "hold_for_human_approval"
    if "medium" in risk_tiers:
        return "hold_for_action_evidence"
    return "allow_bounded_action"


def workflow_action_matrix(manifest: dict[str, Any], action_classes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    action_by_id = {str(row.get("id")): row for row in action_classes if row.get("id")}
    rows: list[dict[str, Any]] = []
    for workflow in active_workflows(manifest):
        action_ids = action_ids_for_workflow(workflow)
        required_evidence = sorted(
            {
                str(item)
                for action_id in action_ids
                for item in action_by_id.get(action_id, {}).get("required_evidence", [])
            }
        )
        mcp_tools = sorted(
            {
                str(tool)
                for action_id in action_ids
                for tool in action_by_id.get(action_id, {}).get("mcp_tools", [])
            }
        )
        rows.append(
            {
                "action_class_ids": action_ids,
                "decision_floor": action_decision_floor(action_ids, action_by_id),
                "maturity_stage": workflow.get("maturity_stage"),
                "mcp_namespaces": [
                    {
                        "access": namespace.get("access"),
                        "namespace": namespace.get("namespace"),
                    }
                    for namespace in workflow_namespaces(workflow)
                ],
                "mcp_tools": mcp_tools,
                "required_evidence": required_evidence,
                "title": workflow.get("title"),
                "workflow_id": workflow.get("id"),
            }
        )
    return rows


def tabletop_cases(profile: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "action_class": "repo_branch_write",
            "expected_decision": "allow_bounded_action",
            "id": "bounded-repo-branch-write",
            "trigger": "A dependency remediation agent writes a scoped branch with policy, authorization, receipt, and correlation evidence."
        },
        {
            "action_class": "production_deployment",
            "expected_decision": "hold_for_human_approval",
            "id": "prod-deploy-without-approval",
            "trigger": "An agent requests deployment into production with a valid policy hash but no approval or risk acceptance."
        },
        {
            "action_class": "credential_or_secret_access",
            "expected_decision": "kill_session_on_runtime_action_signal",
            "id": "secret-in-tool-payload",
            "trigger": "A tool call payload or telemetry event contains a secret or raw token."
        },
        {
            "action_class": "funds_or_irreversible_transaction",
            "expected_decision": "deny_unapproved_high_impact_action",
            "id": "live-funds-movement-request",
            "trigger": "A crypto workflow attempts an irreversible transaction without approval, risk acceptance, or simulation evidence."
        }
    ]


def build_pack(
    *,
    profile: dict[str, Any],
    payloads: dict[str, dict[str, Any]],
    source_artifacts: dict[str, dict[str, Any]],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    action_classes = action_class_rows(profile, source_artifacts)
    matrix = workflow_action_matrix(payloads["workflow_manifest"], action_classes)
    risk_counts = Counter(str(row.get("risk_tier")) for row in action_classes)
    floor_counts = Counter(str(row.get("decision_floor")) for row in matrix)
    registered_action_ids = sorted({action_id for row in matrix for action_id in row.get("action_class_ids", [])})

    return {
        "action_classes": action_classes,
        "action_contract": profile.get("action_contract", {}),
        "action_runtime_pack_id": "security-recipes.agentic-action-runtime.v1",
        "action_runtime_summary": {
            "action_class_count": len(action_classes),
            "critical_or_high_action_count": risk_counts.get("critical", 0) + risk_counts.get("high", 0),
            "decision_floor_counts": dict(sorted(floor_counts.items())),
            "failure_count": len(failures),
            "registered_action_class_count": len(registered_action_ids),
            "required_evidence_source_count": len(profile.get("action_contract", {}).get("required_evidence_sources", [])),
            "source_failure_count": sum(int(artifact.get("failure_count") or 0) for artifact in source_artifacts.values()),
            "workflow_count": len(matrix),
        },
        "commercialization_path": profile.get("commercialization_path", {}),
        "enterprise_adoption_packet": {
            "board_level_claim": profile.get("executive_readout", {}).get("board_level_claim"),
            "default_questions_answered": [
                "Which autonomous action class is being attempted?",
                "Is the action registered for this workflow?",
                "Is context, policy, intent, identity, authorization, egress, handoff, telemetry, approval, and receipt evidence present?",
                "Should the runtime allow, hold, deny, or kill the action?",
                "Which MCP evidence tools explain the decision?"
            ],
            "recommended_first_use": profile.get("executive_readout", {}).get("recommended_first_use"),
            "sales_motion": "Lead with the open action-runtime pack, then sell hosted action firewall APIs, signed action receipts, customer policy adapters, approval validation, and SIEM/SOAR export."
        },
        "executive_readout": profile.get("executive_readout", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "The generated pack proves the action model and evidence shape, not live enforcement in a customer gateway.",
                "treatment": "Bind this pack to MCP gateway middleware, agent host hooks, identity-provider logs, approval systems, and signed run receipts before production enforcement."
            },
            {
                "risk": "New agent hosts, MCP transports, A2A patterns, model capabilities, or skill registries can introduce action classes not represented here.",
                "treatment": "Regenerate the pack after threat-radar review, connector intake, model upgrades, workflow promotion, and incident-derived replay cases."
            },
            {
                "risk": "Human approval can become a rubber stamp if the runtime evidence envelope is incomplete or difficult to inspect.",
                "treatment": "Require approval records to bind the exact action class, workflow, run, policy hash, context hash, identity, and correlation id."
            }
        ],
        "runtime_policy": profile.get("runtime_policy", {}),
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": source_artifacts,
        "standards_alignment": profile.get("standards_alignment", []),
        "tabletop_cases": tabletop_cases(profile),
        "workflow_action_matrix": matrix,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in action runtime pack is stale.")
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
    except ActionRuntimePackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = stable_json(pack)
    if args.check:
        if not output_path.exists():
            print(f"{output_path} is missing; run scripts/generate_agentic_action_runtime_pack.py", file=sys.stderr)
            return 1
        current = output_path.read_text(encoding="utf-8")
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_agentic_action_runtime_pack.py", file=sys.stderr)
            return 1
        if failures:
            print("agentic action runtime pack validation failed:", file=sys.stderr)
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
