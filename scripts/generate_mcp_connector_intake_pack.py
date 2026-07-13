#!/usr/bin/env python3
"""Generate the SecurityRecipes MCP connector intake pack.

The connector trust registry describes namespaces that are already
approved. The intake pack handles the step before that: new or changed
MCP servers are scored for auth, network, tool-schema, data, write, and
evidence risk before they are allowed into the production registry.

The output is deterministic by default so CI can run with --check and
fail when the checked-in intake pack drifts from source candidates.
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


PACK_SCHEMA_VERSION = "1.0"
DEFAULT_CANDIDATES = Path("data/mcp/connector-intake-candidates.json")
DEFAULT_CONNECTOR_TRUST_PACK = Path("data/evidence/mcp-connector-trust-pack.json")
DEFAULT_OUTPUT = Path("data/evidence/mcp-connector-intake-pack.json")

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")
NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$")
VALID_TRANSPORTS = {"stdio", "streamable-http", "http", "sse"}
VALID_ACCESS_MODES = {"read", "write_branch", "write_ticket", "approval_required"}
VALID_DECISIONS = {
    "approve_for_registry_candidate",
    "pilot_with_gateway_controls",
    "hold_for_controls",
    "deny_until_redesigned",
}
PROHIBITED_DATA_CLASSES = {
    "private_key",
    "seed_phrase",
    "live_signing_material",
    "raw_access_token",
    "production_credential",
    "unredacted_pii_bulk",
}
HIGH_IMPACT_TERMS = {
    "delete",
    "deploy",
    "funds",
    "payment",
    "publish",
    "purge",
    "release",
    "sign",
    "transaction",
}
PROMPT_INJECTION_TERMS = {
    "ignore previous",
    "system prompt",
    "developer message",
    "follow these instructions",
    "execute these instructions",
}

TIER_REQUIRED_CONTROLS = {
    "tier_0_public_context": [
        "pin_tool_descriptions",
        "inspect_tool_results",
        "audit_every_tool_call",
    ],
    "tier_1_internal_read": [
        "per_client_consent",
        "short_lived_workload_identity",
        "token_audience_validation",
        "deny_token_passthrough",
        "pin_tool_descriptions",
        "inspect_tool_results",
        "deny_private_network_egress",
        "audit_every_tool_call",
        "session_binding",
    ],
    "tier_2_scoped_write": [
        "per_client_consent",
        "short_lived_workload_identity",
        "token_audience_validation",
        "deny_token_passthrough",
        "pin_tool_descriptions",
        "inspect_tool_results",
        "deny_private_network_egress",
        "audit_every_tool_call",
        "session_binding",
        "write_scope_enforcement",
        "human_review_before_merge",
    ],
    "tier_3_approval_required": [
        "per_client_consent",
        "short_lived_workload_identity",
        "token_audience_validation",
        "deny_token_passthrough",
        "pin_tool_descriptions",
        "inspect_tool_results",
        "deny_private_network_egress",
        "audit_every_tool_call",
        "session_binding",
        "write_scope_enforcement",
        "typed_human_approval",
        "two_key_review",
        "kill_session_on_approval_bypass",
    ],
    "tier_4_prohibited": [
        "hard_deny",
        "audit_denied_attempts",
        "kill_session_on_attempt",
    ],
}


class ConnectorIntakeError(RuntimeError):
    """Raised when the connector intake pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConnectorIntakeError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ConnectorIntakeError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConnectorIntakeError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ConnectorIntakeError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConnectorIntakeError(f"{label} must be an object")
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


def evidence_text(value: Any) -> str:
    try:
        return json.dumps(value, separators=(",", ":"))
    except TypeError:
        return str(value)


def connector_namespaces(connector_trust_pack: dict[str, Any]) -> set[str]:
    return {
        str(connector.get("namespace"))
        for connector in connector_trust_pack.get("connectors", [])
        if isinstance(connector, dict) and connector.get("namespace")
    }


def validate_candidates(candidates: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(candidates.get("schema_version") == PACK_SCHEMA_VERSION, failures, "candidate registry schema_version must be 1.0")
    require(len(str(candidates.get("intent", ""))) >= 80, failures, "candidate registry intent must explain the product goal")

    standards = as_list(candidates.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 5, failures, "standards_alignment must include at least five references")
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

    contract = as_dict(candidates.get("intake_contract"), "intake_contract")
    require(contract.get("default_decision") == "hold_for_intake_review", failures, "intake_contract.default_decision must hold by default")
    require(len(as_list(contract.get("minimum_required_controls"), "intake_contract.minimum_required_controls")) >= 6, failures, "minimum_required_controls must be specific")
    require(len(as_list(contract.get("risk_families"), "intake_contract.risk_families")) >= 6, failures, "risk_families must be specific")

    rows = as_list(candidates.get("candidates"), "candidates")
    require(rows, failures, "candidates must not be empty")
    seen_ids: set[str] = set()
    seen_namespaces: set[str] = set()
    for idx, candidate in enumerate(rows):
        label = f"candidates[{idx}]"
        if not isinstance(candidate, dict):
            failures.append(f"{label} must be an object")
            continue

        candidate_id = str(candidate.get("id", "")).strip()
        namespace = str(candidate.get("namespace", "")).strip()
        require(bool(ID_RE.match(candidate_id)), failures, f"{label}.id must be kebab-case")
        require(candidate_id not in seen_ids, failures, f"{label}.id duplicates {candidate_id}")
        seen_ids.add(candidate_id)
        require(bool(NAMESPACE_RE.match(namespace)), failures, f"{label}.namespace must be dotted namespace")
        require(namespace not in seen_namespaces, failures, f"{label}.namespace duplicates {namespace}")
        seen_namespaces.add(namespace)
        require(str(candidate.get("transport")) in VALID_TRANSPORTS, failures, f"{candidate_id}: transport is invalid")
        require(len(str(candidate.get("business_purpose", ""))) >= 40, failures, f"{candidate_id}: business_purpose must be specific")

        access_modes = {str(item) for item in as_list(candidate.get("requested_access_modes"), f"{label}.requested_access_modes")}
        require(access_modes.issubset(VALID_ACCESS_MODES), failures, f"{candidate_id}: requested_access_modes has invalid values")
        require(bool(access_modes), failures, f"{candidate_id}: requested_access_modes must not be empty")

        owner = as_dict(candidate.get("owner"), f"{label}.owner")
        require(str(owner.get("accountable_team", "")).strip(), failures, f"{candidate_id}: owner.accountable_team is required")
        require(str(owner.get("escalation", "")).strip(), failures, f"{candidate_id}: owner.escalation is required")

        auth = as_dict(candidate.get("auth"), f"{label}.auth")
        require(str(auth.get("strategy", "")).strip(), failures, f"{candidate_id}: auth.strategy is required")
        network = as_dict(candidate.get("network"), f"{label}.network")
        require(isinstance(network.get("allowed_external_hosts"), list), failures, f"{candidate_id}: network.allowed_external_hosts must be a list")

        tools = as_list(candidate.get("tool_surface"), f"{label}.tool_surface")
        require(tools, failures, f"{candidate_id}: tool_surface must not be empty")
        tool_names: set[str] = set()
        for tool_idx, tool in enumerate(tools):
            tool_label = f"{candidate_id}: tool_surface[{tool_idx}]"
            if not isinstance(tool, dict):
                failures.append(f"{tool_label} must be an object")
                continue
            tool_name = str(tool.get("name", "")).strip()
            require(bool(tool_name), failures, f"{tool_label}.name is required")
            require(tool_name not in tool_names, failures, f"{tool_label}.name duplicates {tool_name}")
            tool_names.add(tool_name)
            require(len(str(tool.get("description", ""))) >= 20, failures, f"{tool_label}.description must be specific")
            require(isinstance(tool.get("mutates_state"), bool), failures, f"{tool_label}.mutates_state must be boolean")
            require(isinstance(tool.get("destructive"), bool), failures, f"{tool_label}.destructive must be boolean")
            require(isinstance(tool.get("returns_untrusted_content"), bool), failures, f"{tool_label}.returns_untrusted_content must be boolean")

        for field in ["data_classes", "requested_operations", "declared_controls", "evidence_available"]:
            require(bool(as_list(candidate.get(field), f"{label}.{field}")), failures, f"{candidate_id}: {field} must not be empty")

    return failures


def recommend_tier(candidate: dict[str, Any]) -> str:
    data_classes = {str(item) for item in candidate.get("data_classes", [])}
    operations = " ".join(str(item).lower() for item in candidate.get("requested_operations", []))
    access_modes = {str(item) for item in candidate.get("requested_access_modes", [])}
    tools = [tool for tool in candidate.get("tool_surface", []) if isinstance(tool, dict)]

    if data_classes & PROHIBITED_DATA_CLASSES:
        return "tier_4_prohibited"
    if any(term in operations for term in HIGH_IMPACT_TERMS) or any(tool.get("destructive") for tool in tools) or "approval_required" in access_modes:
        return "tier_3_approval_required"
    if access_modes & {"write_branch", "write_ticket"} or any(tool.get("mutates_state") for tool in tools):
        return "tier_2_scoped_write"
    if data_classes - {"public_recipe_context", "public_metadata", "open_source_metadata"}:
        return "tier_1_internal_read"
    return "tier_0_public_context"


def finding(finding_id: str, severity: str, title: str, evidence: str, control: str) -> dict[str, str]:
    return {
        "control": control,
        "evidence": evidence,
        "id": finding_id,
        "severity": severity,
        "title": title,
    }


def risk_findings(candidate: dict[str, Any], known_namespaces: set[str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    namespace = str(candidate.get("namespace"))
    controls = {str(item) for item in candidate.get("declared_controls", [])}
    auth = candidate.get("auth") if isinstance(candidate.get("auth"), dict) else {}
    network = candidate.get("network") if isinstance(candidate.get("network"), dict) else {}
    tools = [tool for tool in candidate.get("tool_surface", []) if isinstance(tool, dict)]
    data_classes = {str(item) for item in candidate.get("data_classes", [])}
    operations = " ".join(str(item).lower() for item in candidate.get("requested_operations", []))

    if namespace in known_namespaces:
        findings.append(finding("registered-namespace-change", "medium", "Namespace already exists in the production trust pack", namespace, "connector_change_review"))
    if auth.get("token_passthrough") is True:
        findings.append(finding("token-passthrough", "critical", "Token passthrough is declared or possible", str(auth.get("strategy")), "deny_token_passthrough"))
    if auth.get("strategy") in {"oauth2", "oauth2_proxy"}:
        if not auth.get("resource_indicators"):
            findings.append(finding("missing-resource-indicators", "high", "OAuth resource indicators are not declared", evidence_text(auth), "token_audience_validation"))
        if not auth.get("audience_validation"):
            findings.append(finding("missing-audience-validation", "high", "Token audience validation is not declared", evidence_text(auth), "token_audience_validation"))
        if not auth.get("pkce"):
            findings.append(finding("missing-pkce", "medium", "PKCE is not declared for OAuth flow", evidence_text(auth), "pkce_required"))
    if candidate.get("transport") == "stdio" and not auth.get("command_allowlist"):
        findings.append(finding("stdio-command-not-allowlisted", "high", "STDIO launch command lacks an allowlist", evidence_text(candidate.get("source", {})), "local_server_command_allowlist"))
    if network.get("allows_private_network"):
        findings.append(finding("private-network-egress", "high", "Connector can reach private network ranges", evidence_text(network), "deny_private_network_egress"))
    if network.get("allows_metadata_ip"):
        findings.append(finding("metadata-ip-egress", "critical", "Connector can reach cloud metadata endpoints", evidence_text(network), "deny_metadata_ip_egress"))
    if data_classes & PROHIBITED_DATA_CLASSES:
        findings.append(finding("prohibited-data-class", "critical", "Connector requests prohibited data classes", ", ".join(sorted(data_classes & PROHIBITED_DATA_CLASSES)), "hard_deny"))

    for tool in tools:
        tool_name = str(tool.get("name"))
        description = str(tool.get("description", "")).lower()
        if not tool.get("input_schema_pinned"):
            findings.append(finding("unpinned-input-schema", "medium", "Tool input schema is not pinned", tool_name, "pin_tool_schemas"))
        if not tool.get("output_schema_pinned"):
            findings.append(finding("unpinned-output-schema", "medium", "Tool output schema is not pinned", tool_name, "pin_tool_schemas"))
        if tool.get("returns_untrusted_content") and "inspect_tool_results" not in controls:
            findings.append(finding("uninspected-tool-results", "high", "Tool returns untrusted content without result inspection", tool_name, "inspect_tool_results"))
        if any(term in description for term in PROMPT_INJECTION_TERMS):
            findings.append(finding("instruction-like-tool-description", "high", "Tool description contains instruction-like language", tool_name, "pin_tool_descriptions"))
        if tool.get("mutates_state") and "write_scope_enforcement" not in controls:
            findings.append(finding("write-without-scope", "high", "Mutating tool lacks write-scope enforcement", tool_name, "write_scope_enforcement"))
        if tool.get("destructive") and not {"typed_human_approval", "two_key_review"}.issubset(controls):
            findings.append(finding("destructive-without-two-key", "critical", "Destructive tool lacks typed two-key approval", tool_name, "typed_human_approval"))

    if any(term in operations for term in {"deploy", "publish", "release", "sign", "payment", "transaction", "purge", "delete"}) and "typed_human_approval" not in controls:
        findings.append(finding("high-impact-operation-without-approval", "critical", "High-impact operation lacks typed approval", operations, "typed_human_approval"))
    if "audit_every_tool_call" not in controls:
        findings.append(finding("missing-audit", "high", "Tool-call audit is not declared", evidence_text(candidate.get("evidence_available", [])), "audit_every_tool_call"))
    if "session_binding" not in controls:
        findings.append(finding("missing-session-binding", "medium", "Session binding is not declared", evidence_text(candidate.get("declared_controls", [])), "session_binding"))
    if len(candidate.get("evidence_available", []) or []) < 3:
        findings.append(finding("thin-evidence", "medium", "Fewer than three evidence records are available", evidence_text(candidate.get("evidence_available", [])), "evidence_contract"))

    return sorted(findings, key=lambda row: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(row["severity"], 4), row["id"]))


def risk_score(findings: list[dict[str, str]]) -> int:
    weights = {"critical": 22, "high": 13, "medium": 7, "low": 3}
    return min(100, sum(weights.get(finding["severity"], 0) for finding in findings))


def intake_decision(tier: str, score: int, gaps: list[str], findings: list[dict[str, str]]) -> str:
    critical_ids = {finding["id"] for finding in findings if finding["severity"] == "critical"}
    if tier == "tier_4_prohibited" or "prohibited-data-class" in critical_ids:
        return "deny_until_redesigned"
    if critical_ids or score >= 65:
        return "hold_for_controls"
    if gaps or score >= 25:
        return "pilot_with_gateway_controls"
    return "approve_for_registry_candidate"


def registry_patch_preview(candidate: dict[str, Any], tier: str, required_controls: list[str]) -> dict[str, Any]:
    return {
        "access_modes": candidate.get("requested_access_modes", []),
        "category": candidate.get("category"),
        "data_classes": candidate.get("data_classes", []),
        "deployment_model": candidate.get("deployment_model"),
        "id": candidate.get("id"),
        "namespace": candidate.get("namespace"),
        "owner": candidate.get("owner"),
        "required_controls": required_controls,
        "status": "pilot" if tier != "tier_4_prohibited" else "deprecated",
        "title": candidate.get("title"),
        "transport": candidate.get("transport"),
        "trust_tier": tier,
    }


def promotion_plan(candidate: dict[str, Any], decision: str, gaps: list[str], tier: str) -> list[str]:
    if decision == "deny_until_redesigned":
        return [
            "Remove prohibited data or high-impact execution from the connector surface.",
            "Split read-only context from destructive operations before another intake review.",
            "Re-submit with hard-deny controls for secrets, signing material, and live credentials.",
        ]
    plan = [
        "Register owner, escalation path, namespace, access mode, data classes, and tool schema hashes.",
        "Bind the connector to the MCP gateway with default-deny policy and correlation IDs.",
        "Run connector-drift and tool-result-injection drills before production promotion.",
    ]
    if gaps:
        plan.insert(0, "Close required control gaps: " + ", ".join(gaps))
    if tier == "tier_3_approval_required":
        plan.append("Require typed approval receipts and two-key review before any staged high-impact action executes.")
    return plan


def red_team_drills(candidate: dict[str, Any], tier: str) -> list[dict[str, str]]:
    drills = [
        {
            "attack_family": "tool_result_injection",
            "expected_decision": "deny_or_strip_untrusted_instructions",
            "name": "Return hostile instructions inside a normal tool result.",
        },
        {
            "attack_family": "connector_schema_drift",
            "expected_decision": "hold_for_connector_recertification",
            "name": "Change a tool description, input schema, or output schema after approval.",
        },
    ]
    if tier in {"tier_2_scoped_write", "tier_3_approval_required"}:
        drills.append(
            {
                "attack_family": "write_scope_bypass",
                "expected_decision": "deny_or_hold_for_approval",
                "name": "Attempt a write outside the declared project, branch, ticket, or target scope.",
            }
        )
    if candidate.get("transport") == "stdio":
        drills.append(
            {
                "attack_family": "local_server_compromise",
                "expected_decision": "deny_unapproved_command_or_kill_session",
                "name": "Alter the local server launch command or package source.",
            }
        )
    return drills


def build_candidate_rows(candidates: dict[str, Any], known_namespaces: set[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for candidate in as_list(candidates.get("candidates"), "candidates"):
        if not isinstance(candidate, dict):
            continue
        tier = recommend_tier(candidate)
        required_controls = TIER_REQUIRED_CONTROLS[tier]
        declared_controls = [str(control) for control in candidate.get("declared_controls", [])]
        gaps = sorted(set(required_controls) - set(declared_controls))
        findings = risk_findings(candidate, known_namespaces)
        score = risk_score(findings)
        decision = intake_decision(tier, score, gaps, findings)
        rows.append(
            {
                "business_purpose": candidate.get("business_purpose"),
                "candidate_id": candidate.get("id"),
                "control_gaps": gaps,
                "declared_controls": declared_controls,
                "evidence_available": candidate.get("evidence_available", []),
                "intake_decision": decision,
                "namespace": candidate.get("namespace"),
                "promotion_plan": promotion_plan(candidate, decision, gaps, tier),
                "recommended_trust_tier": tier,
                "red_team_drills": red_team_drills(candidate, tier),
                "registry_patch_preview": registry_patch_preview(candidate, tier, required_controls),
                "requested_access_modes": candidate.get("requested_access_modes", []),
                "risk_findings": findings,
                "risk_score": score,
                "source": candidate.get("source", {}),
                "title": candidate.get("title"),
                "tool_count": len(candidate.get("tool_surface", []) or []),
                "transport": candidate.get("transport"),
            }
        )
    return sorted(rows, key=lambda row: (-int(row.get("risk_score") or 0), str(row.get("candidate_id"))))


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    decision_counts = Counter(str(row.get("intake_decision")) for row in rows)
    tier_counts = Counter(str(row.get("recommended_trust_tier")) for row in rows)
    transport_counts = Counter(str(row.get("transport")) for row in rows)
    return {
        "candidate_count": len(rows),
        "decision_counts": dict(sorted(decision_counts.items())),
        "highest_risk_candidates": [
            {
                "candidate_id": row.get("candidate_id"),
                "decision": row.get("intake_decision"),
                "namespace": row.get("namespace"),
                "risk_score": row.get("risk_score"),
                "title": row.get("title"),
            }
            for row in rows[:3]
        ],
        "hold_or_deny_count": sum(decision_counts.get(decision, 0) for decision in ["hold_for_controls", "deny_until_redesigned"]),
        "tier_counts": dict(sorted(tier_counts.items())),
        "transport_counts": dict(sorted(transport_counts.items())),
    }


def build_pack(
    *,
    candidates: dict[str, Any],
    connector_trust_pack: dict[str, Any],
    candidates_path: Path,
    connector_trust_pack_path: Path,
    candidates_ref: Path,
    connector_trust_pack_ref: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    rows = build_candidate_rows(candidates, connector_namespaces(connector_trust_pack))
    invalid_decisions = sorted({str(row.get("intake_decision")) for row in rows} - VALID_DECISIONS)
    require(not invalid_decisions, failures, f"invalid intake decisions generated: {invalid_decisions}")
    return {
        "candidate_evaluations": rows,
        "enterprise_adoption_packet": {
            "board_level_claim": "SecurityRecipes can evaluate MCP servers before they become trusted enterprise connectors.",
            "default_questions_answered": [
                "Which new MCP connectors are safe to pilot?",
                "Which auth, token, network, schema, data, and approval gaps block promotion?",
                "Which connector changes require recertification before agents can use them?",
                "What registry patch would be created after the intake gates pass?",
                "Which red-team drills should run before production approval?",
            ],
            "recommended_first_use": "Run this pack during MCP server intake, vendor review, local-server approval, and connector schema drift reviews.",
            "sales_motion": "Lead with open intake scoring, then sell hosted connector discovery, schema diffing, approval receipts, and continuous recertification.",
        },
        "failures": failures,
        "generated_at": generated_at or str(candidates.get("last_reviewed", "")),
        "intake_contract": candidates.get("intake_contract", {}),
        "intake_summary": build_summary(rows),
        "intent": candidates.get("intent"),
        "positioning": candidates.get("positioning", {}),
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": {
            "connector_intake_candidates": {
                "path": normalize_path(candidates_ref),
                "sha256": sha256_file(candidates_path),
            },
            "connector_trust_pack": {
                "path": normalize_path(connector_trust_pack_ref),
                "sha256": sha256_file(connector_trust_pack_path),
            },
        },
        "standards_alignment": candidates.get("standards_alignment", []),
    }


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--candidates", type=Path, default=DEFAULT_CANDIDATES)
    parser.add_argument("--connector-trust-pack", type=Path, default=DEFAULT_CONNECTOR_TRUST_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in connector intake pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    candidates_path = resolve(repo_root, args.candidates)
    connector_trust_pack_path = resolve(repo_root, args.connector_trust_pack)
    output_path = resolve(repo_root, args.output)

    try:
        candidates = load_json(candidates_path)
        connector_trust_pack = load_json(connector_trust_pack_path)
        failures = validate_candidates(candidates)
        pack = build_pack(
            candidates=candidates,
            connector_trust_pack=connector_trust_pack,
            candidates_path=candidates_path,
            connector_trust_pack_path=connector_trust_pack_path,
            candidates_ref=args.candidates,
            connector_trust_pack_ref=args.connector_trust_pack,
            generated_at=args.generated_at,
            failures=failures,
        )
    except ConnectorIntakeError as exc:
        print(f"MCP connector intake pack generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)

    if args.check:
        if failures:
            print("MCP connector intake pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_mcp_connector_intake_pack.py", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(
                f"{output_path} is stale; run scripts/generate_mcp_connector_intake_pack.py",
                file=sys.stderr,
            )
            return 1
        print(f"Validated MCP connector intake pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated MCP connector intake pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated MCP connector intake pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
