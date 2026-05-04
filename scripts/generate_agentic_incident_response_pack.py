#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic incident response pack.

The pack turns the secure context layer into an enterprise incident
operating model: classify agentic failures, bind them to MCP-readable
evidence, define containment phases, and produce deterministic workflow
response matrices that CI can verify with --check.
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
DEFAULT_PROFILE = Path("data/assurance/agentic-incident-response-profile.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_GATEWAY_POLICY = Path("data/policy/mcp-gateway-policy.json")
DEFAULT_AUTHORIZATION_PACK = Path("data/evidence/mcp-authorization-conformance-pack.json")
DEFAULT_CONNECTOR_TRUST_PACK = Path("data/evidence/mcp-connector-trust-pack.json")
DEFAULT_IDENTITY_LEDGER = Path("data/evidence/agent-identity-delegation-ledger.json")
DEFAULT_RUN_RECEIPT_PACK = Path("data/evidence/agentic-run-receipt-pack.json")
DEFAULT_CONTEXT_TRUST_PACK = Path("data/evidence/secure-context-trust-pack.json")
DEFAULT_CONTEXT_POISONING_GUARD = Path("data/evidence/context-poisoning-guard-pack.json")
DEFAULT_CONTEXT_EGRESS_PACK = Path("data/evidence/context-egress-boundary-pack.json")
DEFAULT_HANDOFF_PACK = Path("data/evidence/agent-handoff-boundary-pack.json")
DEFAULT_A2A_TRUST_PROFILE = Path("data/evidence/a2a-agent-card-trust-profile.json")
DEFAULT_MEMORY_PACK = Path("data/evidence/agent-memory-boundary-pack.json")
DEFAULT_SKILL_PACK = Path("data/evidence/agent-skill-supply-chain-pack.json")
DEFAULT_CATASTROPHIC_ANNEX = Path("data/evidence/agentic-catastrophic-risk-annex.json")
DEFAULT_EXPOSURE_GRAPH = Path("data/evidence/agentic-exposure-graph.json")
DEFAULT_READINESS_SCORECARD = Path("data/evidence/agentic-readiness-scorecard.json")
DEFAULT_CAPABILITY_RISK_REGISTER = Path("data/evidence/agent-capability-risk-register.json")
DEFAULT_MEASUREMENT_PROBE_PACK = Path("data/evidence/agentic-measurement-probe-pack.json")
DEFAULT_RED_TEAM_PACK = Path("data/evidence/agentic-red-team-drill-pack.json")
DEFAULT_SECURE_CONTEXT_EVAL_PACK = Path("data/evidence/secure-context-eval-pack.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-incident-response-pack.json")

SOURCE_REFS = {
    "a2a_agent_card_trust_profile": DEFAULT_A2A_TRUST_PROFILE,
    "agent_capability_risk_register": DEFAULT_CAPABILITY_RISK_REGISTER,
    "agent_handoff_boundary_pack": DEFAULT_HANDOFF_PACK,
    "agent_identity_ledger": DEFAULT_IDENTITY_LEDGER,
    "agent_memory_boundary_pack": DEFAULT_MEMORY_PACK,
    "agent_skill_supply_chain_pack": DEFAULT_SKILL_PACK,
    "agentic_catastrophic_risk_annex": DEFAULT_CATASTROPHIC_ANNEX,
    "agentic_exposure_graph": DEFAULT_EXPOSURE_GRAPH,
    "agentic_measurement_probe_pack": DEFAULT_MEASUREMENT_PROBE_PACK,
    "agentic_readiness_scorecard": DEFAULT_READINESS_SCORECARD,
    "agentic_red_team_drill_pack": DEFAULT_RED_TEAM_PACK,
    "agentic_run_receipt_pack": DEFAULT_RUN_RECEIPT_PACK,
    "context_egress_boundary_pack": DEFAULT_CONTEXT_EGRESS_PACK,
    "context_poisoning_guard_pack": DEFAULT_CONTEXT_POISONING_GUARD,
    "mcp_authorization_conformance": DEFAULT_AUTHORIZATION_PACK,
    "mcp_connector_trust_pack": DEFAULT_CONNECTOR_TRUST_PACK,
    "mcp_gateway_policy": DEFAULT_GATEWAY_POLICY,
    "secure_context_eval_pack": DEFAULT_SECURE_CONTEXT_EVAL_PACK,
    "secure_context_trust_pack": DEFAULT_CONTEXT_TRUST_PACK,
    "workflow_manifest": DEFAULT_MANIFEST,
}

EVIDENCE_ID_TO_SOURCE = {
    "a2a_agent_card_trust_profile": "a2a_agent_card_trust_profile",
    "agent_capability_risk_register": "agent_capability_risk_register",
    "agent_handoff_boundary_pack": "agent_handoff_boundary_pack",
    "agent_identity_ledger": "agent_identity_ledger",
    "agent_memory_boundary_pack": "agent_memory_boundary_pack",
    "agent_skill_supply_chain_pack": "agent_skill_supply_chain_pack",
    "agentic_catastrophic_risk_annex": "agentic_catastrophic_risk_annex",
    "agentic_exposure_graph": "agentic_exposure_graph",
    "agentic_measurement_probe_pack": "agentic_measurement_probe_pack",
    "agentic_readiness_scorecard": "agentic_readiness_scorecard",
    "agentic_red_team_drill_pack": "agentic_red_team_drill_pack",
    "agentic_run_receipt_pack": "agentic_run_receipt_pack",
    "context_egress_boundary_pack": "context_egress_boundary_pack",
    "context_poisoning_guard_pack": "context_poisoning_guard_pack",
    "mcp_authorization_conformance": "mcp_authorization_conformance",
    "mcp_connector_trust_pack": "mcp_connector_trust_pack",
    "mcp_gateway_policy": "mcp_gateway_policy",
    "secure_context_eval_pack": "secure_context_eval_pack",
    "secure_context_trust_pack": "secure_context_trust_pack",
}

SEVERITY_ORDER = {"sev3": 1, "sev2": 2, "sev1": 3, "sev0": 4}
HIGH_IMPACT_HINTS = {
    "approval_required",
    "deploy",
    "funds",
    "identity",
    "payment",
    "production",
    "quarantine",
    "registry",
    "secret",
    "wallet",
}


class IncidentResponsePackError(RuntimeError):
    """Raised when the incident response pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise IncidentResponsePackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise IncidentResponsePackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise IncidentResponsePackError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IncidentResponsePackError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise IncidentResponsePackError(f"{label} must be a list")
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
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must describe the product goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 6, failures, "standards_alignment must include incident response, AI agent, MCP, and AI deployment references")
    seen_standards: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in seen_standards, failures, f"{standard_id}: duplicate standard id")
        seen_standards.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 60, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("incident_contract"), "incident_contract")
    require(
        contract.get("default_state") == "incident_untrusted_until_receipt_context_identity_and_tool_evidence_are_correlated",
        failures,
        "incident_contract.default_state must fail closed",
    )
    required_sources = {str(item) for item in as_list(contract.get("required_evidence_sources"), "incident_contract.required_evidence_sources")}
    require(len(required_sources) >= int(contract.get("minimum_required_evidence_sources") or 0), failures, "required evidence source count below minimum")
    missing_sources = sorted(required_sources - set(EVIDENCE_ID_TO_SOURCE))
    require(not missing_sources, failures, f"unknown required evidence sources: {missing_sources}")
    require(
        len(as_list(contract.get("required_runtime_fields"), "incident_contract.required_runtime_fields")) >= 18,
        failures,
        "runtime fields must cover incident, run, identity, context, MCP, containment, replay, and impact",
    )

    phases = as_list(profile.get("response_phases"), "response_phases")
    require(len(phases) >= int(contract.get("minimum_response_phases") or 0), failures, "response phases below minimum")
    seen_phases: set[str] = set()
    for idx, phase in enumerate(phases):
        item = as_dict(phase, f"response_phases[{idx}]")
        phase_id = str(item.get("id", "")).strip()
        require(bool(phase_id), failures, f"response_phases[{idx}].id is required")
        require(phase_id not in seen_phases, failures, f"{phase_id}: duplicate phase id")
        seen_phases.add(phase_id)
        require(len(str(item.get("objective", ""))) >= 80, failures, f"{phase_id}: objective must be specific")
        require(len(as_list(item.get("minimum_evidence"), f"{phase_id}.minimum_evidence")) >= 4, failures, f"{phase_id}: minimum evidence is incomplete")
        require(len(as_list(item.get("mcp_tools"), f"{phase_id}.mcp_tools")) >= 2, failures, f"{phase_id}: MCP tools are required")

    incident_classes = as_list(profile.get("incident_classes"), "incident_classes")
    require(len(incident_classes) >= int(contract.get("minimum_incident_classes") or 0), failures, "incident classes below minimum")
    seen_classes: set[str] = set()
    for idx, incident_class in enumerate(incident_classes):
        item = as_dict(incident_class, f"incident_classes[{idx}]")
        class_id = str(item.get("id", "")).strip()
        require(bool(class_id), failures, f"incident_classes[{idx}].id is required")
        require(class_id not in seen_classes, failures, f"{class_id}: duplicate class id")
        seen_classes.add(class_id)
        require(str(item.get("default_severity")) in SEVERITY_ORDER, failures, f"{class_id}: default severity must be sev0..sev3")
        require(len(as_list(item.get("kill_signals"), f"{class_id}.kill_signals")) >= 2, failures, f"{class_id}: kill signals are required")
        linked = {str(evidence) for evidence in as_list(item.get("linked_evidence"), f"{class_id}.linked_evidence")}
        require(bool(linked), failures, f"{class_id}: linked evidence is required")
        require(not sorted(linked - set(EVIDENCE_ID_TO_SOURCE)), failures, f"{class_id}: unknown linked evidence")
        require(len(as_list(item.get("mcp_tools"), f"{class_id}.mcp_tools")) >= 2, failures, f"{class_id}: MCP tools are required")

    return failures


def load_sources(repo_root: Path, refs: dict[str, Path]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    payloads: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for source_id, ref in refs.items():
        path = resolve(repo_root, ref)
        try:
            payloads[source_id] = load_json(path)
        except IncidentResponsePackError as exc:
            failures.append(f"{source_id}: {exc}")
    return payloads, failures


def validate_sources(payloads: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    required = set(SOURCE_REFS)
    missing = sorted(required - set(payloads))
    require(not missing, failures, f"missing source payloads: {missing}")
    for source_id, payload in payloads.items():
        if source_id == "workflow_manifest":
            require(payload.get("schema_version") == "1.0", failures, "workflow_manifest schema_version must be 1.0")
            continue
        require(payload.get("schema_version") == "1.0", failures, f"{source_id} schema_version must be 1.0")
        source_failures = payload.get("failures")
        if isinstance(source_failures, list) and source_failures:
            failures.extend(f"{source_id}: {failure}" for failure in source_failures)
    return failures


def build_source_artifacts(
    *,
    repo_root: Path,
    refs: dict[str, Path],
    payloads: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    artifacts: dict[str, dict[str, Any]] = {}
    for source_id, ref in refs.items():
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


def index_by(rows: list[Any], key: str) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        item_key = str(row.get(key, "")).strip()
        if item_key:
            output[item_key] = row
    return output


def active_workflows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [row for row in manifest.get("workflows", []) if isinstance(row, dict)]
    return [row for row in rows if str(row.get("status", "")).lower() == "active"]


def workflow_namespaces(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in workflow.get("mcp_context", []) if isinstance(row, dict)]


def path_for_evidence_id(evidence_id: str, source_artifacts: dict[str, dict[str, Any]]) -> str | None:
    source_id = EVIDENCE_ID_TO_SOURCE.get(evidence_id)
    artifact = source_artifacts.get(source_id or "")
    return str(artifact.get("path")) if isinstance(artifact, dict) else None


def incident_class_rows(profile: dict[str, Any], source_artifacts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for incident_class in profile["incident_classes"]:
        linked = [str(item) for item in incident_class.get("linked_evidence", [])]
        rows.append(
            {
                "default_decision": incident_class.get("default_decision"),
                "default_severity": incident_class.get("default_severity"),
                "evidence_paths": [
                    path for evidence_id in linked
                    if (path := path_for_evidence_id(evidence_id, source_artifacts))
                ],
                "id": incident_class.get("id"),
                "kill_signals": incident_class.get("kill_signals", []),
                "linked_evidence": linked,
                "mcp_tools": incident_class.get("mcp_tools", []),
                "title": incident_class.get("title"),
            }
        )
    return rows


def workflow_signal_text(workflow: dict[str, Any]) -> str:
    values: list[str] = [
        str(workflow.get("id", "")),
        str(workflow.get("title", "")),
        " ".join(str(item) for item in workflow.get("kill_signals", []) if item),
    ]
    for namespace in workflow_namespaces(workflow):
        values.extend([str(namespace.get("namespace", "")), str(namespace.get("access", "")), str(namespace.get("purpose", ""))])
    scope = workflow.get("scope")
    if isinstance(scope, dict):
        values.extend(str(item) for item in scope.get("forbidden_paths", []) if item)
    return " ".join(values).lower()


def high_impact_workflow(workflow: dict[str, Any], capability: dict[str, Any] | None) -> bool:
    if capability and str(capability.get("risk_tier", "")).lower() == "high":
        return True
    signal = workflow_signal_text(workflow)
    return any(hint in signal for hint in HIGH_IMPACT_HINTS)


def assigned_incident_classes(workflow: dict[str, Any], capability: dict[str, Any] | None) -> list[str]:
    classes = {
        "context-poisoning",
        "evidence-integrity-gap",
        "identity-scope-abuse",
        "mcp-authorization-confused-deputy",
        "mcp-tool-misuse",
    }
    signal = workflow_signal_text(workflow)
    if "handoff" in signal or "agent" in signal or workflow_namespaces(workflow):
        classes.add("agent-handoff-leakage")
    if {"memory", "skill", "hook", "rules", "package"} & set(signal.replace("/", " ").replace("-", " ").split()):
        classes.add("memory-or-skill-compromise")
    else:
        classes.add("memory-or-skill-compromise")
    if high_impact_workflow(workflow, capability):
        classes.add("high-impact-autonomy-near-miss")
    return sorted(classes)


def workflow_severity_floor(capability: dict[str, Any] | None, class_ids: list[str]) -> str:
    risk_tier = str((capability or {}).get("risk_tier", "")).lower()
    if risk_tier == "high" and "high-impact-autonomy-near-miss" in class_ids:
        return "sev0"
    if risk_tier in {"high", "medium"}:
        return "sev1"
    return "sev2"


def default_response_decision(severity_floor: str) -> str:
    if severity_floor == "sev0":
        return "kill_session_and_escalate_board"
    if severity_floor == "sev1":
        return "contain_and_open_war_room"
    return "hold_for_forensics"


def containment_actions_for(workflow: dict[str, Any], class_ids: list[str]) -> list[str]:
    actions = [
        "pause_agent_run",
        "preserve_run_receipt",
        "snapshot_context_source_hashes",
        "attach_correlation_id_to_incident",
    ]
    if "identity-scope-abuse" in class_ids:
        actions.append("revoke_or_rotate_delegated_identity")
    if "mcp-tool-misuse" in class_ids or "mcp-authorization-confused-deputy" in class_ids:
        actions.append("freeze_mcp_namespace_or_scope")
    if "context-poisoning" in class_ids:
        actions.append("hold_context_source_promotion")
    if "agent-handoff-leakage" in class_ids:
        actions.append("disable_remote_agent_or_handoff_profile")
    if "memory-or-skill-compromise" in class_ids:
        actions.append("quarantine_memory_or_skill_artifact")
    if "high-impact-autonomy-near-miss" in class_ids:
        actions.append("require_incident_commander_and_risk_owner_review")
    namespace_count = len(workflow_namespaces(workflow))
    if namespace_count > 0:
        actions.append(f"review_{namespace_count}_workflow_mcp_namespaces")
    return actions


def workflow_response_matrix(
    *,
    manifest: dict[str, Any],
    readiness: dict[str, Any],
    capability_register: dict[str, Any],
    exposure_graph: dict[str, Any],
    incident_classes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    readiness_by_workflow = index_by(
        [row for row in readiness.get("workflow_readiness", []) if isinstance(row, dict)],
        "workflow_id",
    )
    capability_by_workflow = index_by(
        [row for row in capability_register.get("workflow_capability_risks", []) if isinstance(row, dict)],
        "workflow_id",
    )
    exposure_counter: Counter[str] = Counter()
    for path in exposure_graph.get("exposure_paths", []):
        if isinstance(path, dict):
            workflow_id = str(path.get("workflow_id", "")).strip()
            if workflow_id and int(path.get("score") or 0) >= 70:
                exposure_counter[workflow_id] += 1

    rows: list[dict[str, Any]] = []
    for workflow in active_workflows(manifest):
        workflow_id = str(workflow.get("id"))
        readiness_row = readiness_by_workflow.get(workflow_id, {})
        capability = capability_by_workflow.get(workflow_id, {})
        class_ids = assigned_incident_classes(workflow, capability)
        floor = workflow_severity_floor(capability, class_ids)
        namespace_rows = workflow_namespaces(workflow)
        rows.append(
            {
                "assigned_incident_class_ids": class_ids,
                "containment_actions": containment_actions_for(workflow, class_ids),
                "default_response_decision": default_response_decision(floor),
                "high_score_exposure_path_count": exposure_counter[workflow_id],
                "maturity_stage": workflow.get("maturity_stage"),
                "mcp_namespaces": [
                    {
                        "access": namespace.get("access"),
                        "namespace": namespace.get("namespace"),
                    }
                    for namespace in namespace_rows
                ],
                "readiness_decision": readiness_row.get("decision"),
                "readiness_score": readiness_row.get("score"),
                "replay_requirements": [
                    "convert incident timeline into secure-context eval case",
                    "add red-team drill or measurement probe before workflow recertification",
                    "re-run readiness scorecard after containment and policy patch",
                ],
                "risk_decision": capability.get("decision"),
                "risk_tier": capability.get("risk_tier"),
                "severity_floor": floor,
                "title": workflow.get("title"),
                "workflow_id": workflow_id,
            }
        )
    return rows


def tabletop_cases(profile: dict[str, Any]) -> list[dict[str, Any]]:
    examples = [
        (
            "poisoned-context-returned-to-agent",
            "context-poisoning",
            "A retrieved source contains hidden tool override text and the poisoning guard produces an actionable critical finding.",
            "contain_and_open_war_room",
        ),
        (
            "mcp-token-forwarded-to-remote-agent",
            "mcp-authorization-confused-deputy",
            "A tool result attempts to pass an MCP access token into a remote A2A agent handoff.",
            "kill_session_and_escalate_board",
        ),
        (
            "production-write-without-approval",
            "high-impact-autonomy-near-miss",
            "An agent requests a production write path with no linked approval, risk acceptance, or receipt evidence.",
            "kill_session_and_escalate_board",
        ),
        (
            "missing-receipt-after-agent-drift",
            "evidence-integrity-gap",
            "A model or connector changed and the run cannot be replayed from current receipt and source hashes.",
            "hold_for_forensics",
        ),
    ]
    class_by_id = {
        str(row.get("id")): row
        for row in profile.get("incident_classes", [])
        if isinstance(row, dict)
    }
    return [
        {
            "expected_decision": expected_decision,
            "id": case_id,
            "incident_class_id": class_id,
            "minimum_mcp_tools": class_by_id.get(class_id, {}).get("mcp_tools", [])[:4],
            "trigger": trigger,
        }
        for case_id, class_id, trigger, expected_decision in examples
    ]


def build_pack(
    *,
    profile: dict[str, Any],
    source_payloads: dict[str, dict[str, Any]],
    source_artifacts: dict[str, dict[str, Any]],
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    incident_classes = incident_class_rows(profile, source_artifacts)
    matrix = workflow_response_matrix(
        manifest=source_payloads["workflow_manifest"],
        readiness=source_payloads["agentic_readiness_scorecard"],
        capability_register=source_payloads["agent_capability_risk_register"],
        exposure_graph=source_payloads["agentic_exposure_graph"],
        incident_classes=incident_classes,
    )
    severity_counts = Counter(row.get("default_severity") for row in incident_classes)
    decision_counts = Counter(row.get("default_response_decision") for row in matrix)

    return {
        "commercialization_path": profile.get("commercialization_path", {}),
        "enterprise_adoption_packet": {
            "board_level_claim": profile.get("executive_readout", {}).get("board_level_claim"),
            "default_questions_answered": [
                "Which class of agentic incident occurred?",
                "Which run, identity, context package, MCP namespace, and handoff were affected?",
                "Should the platform monitor, hold for forensics, contain, or kill the session?",
                "Which evidence packs prove blast radius and containment?",
                "Which replay cases must pass before the workflow can be recertified?"
            ],
            "recommended_first_use": profile.get("executive_readout", {}).get("recommended_first_use"),
            "sales_motion": "Lead with the open incident model, then sell hosted receipt vaulting, SIEM/SOAR export, replay orchestration, customer incident readouts, and MCP kill-switch automation."
        },
        "executive_readout": profile.get("executive_readout", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "incident_classes": incident_classes,
        "incident_contract": profile.get("incident_contract", {}),
        "incident_response_pack_id": "security-recipes.agentic-incident-response.v1",
        "incident_response_summary": {
            "class_count": len(incident_classes),
            "decision_counts": dict(sorted(decision_counts.items())),
            "failure_count": len(failures),
            "required_evidence_source_count": len(profile.get("incident_contract", {}).get("required_evidence_sources", [])),
            "response_phase_count": len(profile.get("response_phases", [])),
            "sev0_class_count": severity_counts.get("sev0", 0),
            "sev1_class_count": severity_counts.get("sev1", 0),
            "source_failure_count": sum(int(artifact.get("failure_count") or 0) for artifact in source_artifacts.values()),
            "workflow_count": len(matrix),
        },
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "The generated pack proves the response model and source evidence shape, not live customer telemetry collection.",
                "treatment": "Bind the pack to hosted MCP logs, SIEM events, identity provider revocation logs, source-host review events, and signed receipt storage before production incident automation."
            },
            {
                "risk": "Incident class coverage can lag behind new agent host, MCP, A2A, memory, or skill behaviors.",
                "treatment": "Review incident classes during model upgrades, connector promotions, prompt-library changes, and quarterly threat radar updates."
            },
            {
                "risk": "Replay evidence can prove recurrence controls only when the failing context, prompt, tool result, and policy decision are preserved.",
                "treatment": "Treat missing receipt, correlation id, context hash, or authorization decision as a hold_for_forensics condition."
            }
        ],
        "response_phases": profile.get("response_phases", []),
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": source_artifacts,
        "standards_alignment": profile.get("standards_alignment", []),
        "tabletop_cases": tabletop_cases(profile),
        "workflow_response_matrix": matrix,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in incident response pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    output_path = resolve(repo_root, args.output)
    refs = dict(SOURCE_REFS)

    try:
        profile = load_json(profile_path)
        source_payloads, load_failures = load_sources(repo_root, refs)
        source_artifacts = build_source_artifacts(repo_root=repo_root, refs=refs, payloads=source_payloads)
        failures = [
            *validate_profile(profile),
            *load_failures,
            *validate_sources(source_payloads),
        ]
        pack = build_pack(
            profile=profile,
            source_payloads=source_payloads,
            source_artifacts=source_artifacts,
            generated_at=args.generated_at,
            failures=failures,
        )
    except IncidentResponsePackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = stable_json(pack)
    if args.check:
        if not output_path.exists():
            print(f"{output_path} is missing; run scripts/generate_agentic_incident_response_pack.py", file=sys.stderr)
            return 1
        current = output_path.read_text(encoding="utf-8")
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_agentic_incident_response_pack.py", file=sys.stderr)
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
