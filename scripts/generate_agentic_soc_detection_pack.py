#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic SOC detection pack.

The pack turns existing secure-context evidence into SOC-operable
detection rules for agentic AI and MCP systems. It deliberately uses
metadata, hashes, policy decisions, run receipts, and trace links rather
than raw prompts or tool payloads.
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
DEFAULT_PROFILE = Path("data/assurance/agentic-soc-detection-profile.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_TELEMETRY_CONTRACT = Path("data/evidence/agentic-telemetry-contract.json")
DEFAULT_INCIDENT_RESPONSE_PACK = Path("data/evidence/agentic-incident-response-pack.json")
DEFAULT_THREAT_RADAR = Path("data/evidence/agentic-threat-radar.json")
DEFAULT_REPLAY_HARNESS = Path("data/evidence/agentic-red-team-replay-harness.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-soc-detection-pack.json")

REQUIRED_RULE_IDS = {
    "mcp-token-passthrough-or-audience-mismatch",
    "mcp-tool-surface-drift-critical",
    "context-poisoning-retrieval",
    "secret-or-cross-tenant-telemetry",
    "approval-bypass-high-impact-action",
    "browser-agent-url-exfiltration",
    "unbounded-agent-loop-or-cost-runaway",
    "shadow-mcp-server-or-unknown-connector",
    "source-freshness-or-standard-drift",
    "red-team-replay-regression",
}

SEVERITY_ORDER = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
}


class SocDetectionError(RuntimeError):
    """Raised when the detection pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SocDetectionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SocDetectionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SocDetectionError(f"{path} root must be a JSON object")
    return payload


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SocDetectionError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SocDetectionError(f"{label} must be a list")
    return value


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def normalize_path(path: Path) -> str:
    return path.as_posix()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def source_failure_count(payloads: dict[str, dict[str, Any]]) -> int:
    count = 0
    for payload in payloads.values():
        failures = payload.get("failures")
        if isinstance(failures, list):
            count += len(failures)
    return count


def rows_by_id(rows: list[Any], key: str) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and row.get(key):
            output[str(row.get(key))] = row
    return output


def workflow_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return rows_by_id(as_list(manifest.get("workflows"), "workflow_manifest.workflows"), "id")


def telemetry_workflow_by_id(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return rows_by_id(
        as_list(contract.get("workflow_telemetry_contracts"), "agentic_telemetry_contract.workflow_telemetry_contracts"),
        "workflow_id",
    )


def incidents_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return rows_by_id(as_list(pack.get("incident_classes"), "agentic_incident_response_pack.incident_classes"), "id")


def replay_by_workflow(pack: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    by_workflow: dict[str, list[dict[str, Any]]] = {}
    for row in as_list(pack.get("replay_fixtures"), "agentic_red_team_replay_harness.replay_fixtures"):
        if not isinstance(row, dict):
            continue
        workflow_id = str(row.get("workflow_id") or "").strip()
        if workflow_id:
            by_workflow.setdefault(workflow_id, []).append(row)
    return by_workflow


def validate_condition(condition: dict[str, Any], failures: list[str], label: str) -> None:
    field = str(condition.get("field", "")).strip()
    operator = str(condition.get("operator", "")).strip()
    require(bool(field), failures, f"{label}.field is required")
    require(
        operator in {
            "bool_true",
            "contains_any",
            "equals",
            "greater_equal",
            "in",
            "not_equals",
            "not_equals_field",
        },
        failures,
        f"{label}.operator is unsupported",
    )
    if operator not in {"bool_true"}:
        require("value" in condition, failures, f"{label}.value is required for {operator}")


def validate_profile(profile: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must describe the SOC product goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 8, failures, "standards_alignment must include current AI, MCP, SOC, and telemetry references")
    seen_standards: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in seen_standards, failures, f"{standard_id}: duplicate standard id")
        seen_standards.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 60, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("detection_contract"), "detection_contract")
    require(
        contract.get("default_state") == "soc_untrusted_until_trace_contract_ready",
        failures,
        "detection contract default_state must fail closed",
    )
    require(
        set(contract.get("required_source_packs", []))
        == {
            "workflow_manifest",
            "agentic_telemetry_contract",
            "agentic_incident_response_pack",
            "agentic_threat_radar",
            "agentic_red_team_replay_harness",
        },
        failures,
        "detection contract must name every required source pack",
    )
    require(len(contract.get("required_common_attributes", [])) >= 10, failures, "required_common_attributes are incomplete")

    targets = as_list(profile.get("siem_targets"), "siem_targets")
    target_ids = {str(item.get("id")) for item in targets if isinstance(item, dict)}
    require({"splunk", "microsoft_sentinel", "chronicle"}.issubset(target_ids), failures, "SIEM targets must include Splunk, Sentinel, and Chronicle")

    rules = as_list(profile.get("detection_rules"), "detection_rules")
    rule_ids: set[str] = set()
    require(len(rules) >= int(contract.get("minimum_detection_rules", 9)), failures, "detection rule count is below minimum")
    for idx, rule in enumerate(rules):
        item = as_dict(rule, f"detection_rules[{idx}]")
        rule_id = str(item.get("id", "")).strip()
        rule_ids.add(rule_id)
        require(rule_id not in {"", "None"}, failures, f"detection_rules[{idx}].id is required")
        require(str(item.get("severity")) in SEVERITY_ORDER, failures, f"{rule_id}: unsupported severity")
        require(str(item.get("decision", "")).startswith("soc_"), failures, f"{rule_id}: decision must be SOC-shaped")
        require(len(as_list(item.get("event_classes"), f"{rule_id}.event_classes")) >= 1, failures, f"{rule_id}: event_classes are required")
        require(len(as_list(item.get("mapped_risks"), f"{rule_id}.mapped_risks")) >= 2, failures, f"{rule_id}: mapped_risks must be specific")
        require(len(as_list(item.get("required_attributes"), f"{rule_id}.required_attributes")) >= 4, failures, f"{rule_id}: required_attributes are incomplete")
        require(len(str(item.get("response_playbook", ""))) >= 80, failures, f"{rule_id}: response_playbook must be actionable")
        for cond_idx, condition in enumerate(as_list(item.get("all_match_conditions"), f"{rule_id}.all_match_conditions")):
            validate_condition(as_dict(condition, f"{rule_id}.all_match_conditions[{cond_idx}]"), failures, f"{rule_id}.all_match_conditions[{cond_idx}]")
        for cond_idx, condition in enumerate(as_list(item.get("any_match_conditions"), f"{rule_id}.any_match_conditions")):
            validate_condition(as_dict(condition, f"{rule_id}.any_match_conditions[{cond_idx}]"), failures, f"{rule_id}.any_match_conditions[{cond_idx}]")
    require(REQUIRED_RULE_IDS.issubset(rule_ids), failures, "profile is missing one or more required SOC detection rules")
    return failures


def validate_sources(source_payloads: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for label, payload in source_payloads.items():
        require(payload.get("schema_version") == "1.0", failures, f"{label} schema_version must be 1.0")
    require(source_failure_count(source_payloads) == 0, failures, "source packs must have zero validation failures")

    workflows = set(workflow_by_id(source_payloads["workflow_manifest"]))
    telemetry = set(telemetry_workflow_by_id(source_payloads["agentic_telemetry_contract"]))
    replay = set(replay_by_workflow(source_payloads["agentic_red_team_replay_harness"]))
    require(bool(workflows), failures, "workflow manifest must include workflows")
    require(workflows == telemetry, failures, "telemetry workflows must match workflow manifest")
    require(workflows.issubset(replay), failures, "red-team replay harness must include every workflow")
    require(bool(incidents_by_id(source_payloads["agentic_incident_response_pack"])), failures, "incident pack must include incident classes")
    require(bool(source_payloads["agentic_threat_radar"].get("capability_coverage")), failures, "threat radar must include capability coverage")
    return failures


def quote_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))


def condition_to_splunk(condition: dict[str, Any]) -> str:
    field = str(condition.get("field"))
    operator = str(condition.get("operator"))
    value = condition.get("value")
    if operator == "bool_true":
        return f'{field}=true'
    if operator == "in":
        values = " OR ".join(f'{field}={quote_value(item)}' for item in value)
        return f"({values})"
    if operator == "equals":
        return f"{field}={quote_value(value)}"
    if operator == "not_equals":
        return f"NOT {field}={quote_value(value)}"
    if operator == "not_equals_field":
        return f"{field}!={value}"
    if operator == "greater_equal":
        return f"{field}>={value}"
    if operator == "contains_any":
        values = " OR ".join(f'{field}=*{str(item)}*' for item in value)
        return f"({values})"
    return f"{field}=*"


def condition_to_kql(condition: dict[str, Any]) -> str:
    field = str(condition.get("field"))
    operator = str(condition.get("operator"))
    value = condition.get("value")
    ref = f'tostring(Attributes["{field}"])'
    if field == "event_class":
        ref = "EventClass"
    if operator == "bool_true":
        return f'tolower({ref}) in ("true", "1", "yes")'
    if operator == "in":
        values = ", ".join(quote_value(item) for item in value)
        return f"{ref} in ({values})"
    if operator == "equals":
        return f"{ref} == {quote_value(value)}"
    if operator == "not_equals":
        return f"{ref} != {quote_value(value)}"
    if operator == "not_equals_field":
        return f'{ref} != tostring(Attributes["{value}"])'
    if operator == "greater_equal":
        return f"todouble({ref}) >= {value}"
    if operator == "contains_any":
        values = " or ".join(f"{ref} contains {quote_value(item)}" for item in value)
        return f"({values})"
    return f"isnotempty({ref})"


def condition_to_chronicle(condition: dict[str, Any]) -> str:
    field = str(condition.get("field")).replace(".", "_")
    operator = str(condition.get("operator"))
    value = condition.get("value")
    ref = f"$e.principal.labels.{field}"
    if condition.get("field") == "event_class":
        ref = "$e.metadata.event_type"
    if operator == "bool_true":
        return f'{ref} = "true"'
    if operator == "in":
        values = " or ".join(f"{ref} = {quote_value(item)}" for item in value)
        return f"({values})"
    if operator == "equals":
        return f"{ref} = {quote_value(value)}"
    if operator == "not_equals":
        return f"{ref} != {quote_value(value)}"
    if operator == "not_equals_field":
        return f"{ref} != $e.principal.labels.{str(value).replace('.', '_')}"
    if operator == "greater_equal":
        return f"{ref} >= {value}"
    if operator == "contains_any":
        values = " or ".join(f"{ref} = /.*{str(item)}.*/" for item in value)
        return f"({values})"
    return f"{ref} != \"\""


def join_conditions(conditions: list[dict[str, Any]], renderer: Any, joiner: str) -> str:
    rendered = [renderer(condition) for condition in conditions]
    if not rendered:
        return ""
    if len(rendered) == 1:
        return rendered[0]
    return "(" + f" {joiner} ".join(rendered) + ")"


def build_queries(rule: dict[str, Any], profile: dict[str, Any]) -> dict[str, str]:
    all_conditions = [as_dict(item, "all_match_condition") for item in rule.get("all_match_conditions", [])]
    any_conditions = [as_dict(item, "any_match_condition") for item in rule.get("any_match_conditions", [])]
    splunk_parts = [
        'index=agentic_ai',
        join_conditions(all_conditions, condition_to_splunk, "AND"),
        join_conditions(any_conditions, condition_to_splunk, "OR"),
    ]
    kql_parts = [
        "AgenticAIEvents",
        "| where " + join_conditions(all_conditions, condition_to_kql, "and") if all_conditions else "",
        "| where " + join_conditions(any_conditions, condition_to_kql, "or") if any_conditions else "",
        f'| extend DetectionRule="{rule.get("id")}", Severity="{rule.get("severity")}"',
    ]
    chronicle_conditions = [
        join_conditions(all_conditions, condition_to_chronicle, "and"),
        join_conditions(any_conditions, condition_to_chronicle, "or"),
    ]
    chronicle_where = " and ".join(f"({part})" for part in chronicle_conditions if part)
    chronicle_default = '$e.metadata.event_type != ""'
    return {
        "splunk_spl": " ".join(part for part in splunk_parts if part),
        "microsoft_sentinel_kql": "\n".join(part for part in kql_parts if part),
        "chronicle_yara_l": (
            f'rule {str(rule.get("id")).replace("-", "_")} {{\n'
            "  events:\n"
            f"    {chronicle_where or chronicle_default}\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
    }


def build_detection_rules(profile: dict[str, Any]) -> list[dict[str, Any]]:
    rules = []
    for rule in sorted(profile.get("detection_rules", []), key=lambda item: (-SEVERITY_ORDER.get(str(item.get("severity")), 0), str(item.get("id")))):
        enriched = dict(rule)
        enriched["severity_score"] = SEVERITY_ORDER.get(str(rule.get("severity")), 0)
        enriched["siem_queries"] = build_queries(rule, profile)
        rules.append(enriched)
    return rules


def workflow_namespaces(workflow: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(context.get("namespace"))
            for context in workflow.get("mcp_context", []) or []
            if isinstance(context, dict) and context.get("namespace")
        }
    )


def rule_ids_for_workflow(workflow: dict[str, Any], rules: list[dict[str, Any]]) -> list[str]:
    namespaces = workflow_namespaces(workflow)
    output: set[str] = {
        "secret-or-cross-tenant-telemetry",
        "source-freshness-or-standard-drift",
        "red-team-replay-regression",
        "unbounded-agent-loop-or-cost-runaway",
    }
    if namespaces:
        output.update(
            {
                "mcp-token-passthrough-or-audience-mismatch",
                "mcp-tool-surface-drift-critical",
                "shadow-mcp-server-or-unknown-connector",
            }
        )
    if any("context" in namespace or "findings" in namespace for namespace in namespaces):
        output.add("context-poisoning-retrieval")
    if any("browser" in namespace for namespace in namespaces) or workflow.get("id") == "browser-agent-boundary":
        output.add("browser-agent-url-exfiltration")
    if any("write" in str(context.get("access", "")) for context in workflow.get("mcp_context", []) or [] if isinstance(context, dict)):
        output.add("approval-bypass-high-impact-action")
    valid = {str(rule.get("id")) for rule in rules}
    return sorted(rule_id for rule_id in output if rule_id in valid)


def build_workflow_overlays(
    *,
    workflows: dict[str, dict[str, Any]],
    telemetry: dict[str, dict[str, Any]],
    replay: dict[str, list[dict[str, Any]]],
    rules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    overlays = []
    for workflow_id in sorted(workflows):
        workflow = workflows[workflow_id]
        telemetry_row = telemetry.get(workflow_id, {})
        replay_rows = replay.get(workflow_id, [])
        rule_ids = rule_ids_for_workflow(workflow, rules)
        overlays.append(
            {
                "agent_classes": workflow.get("default_agents", []),
                "detection_rule_ids": rule_ids,
                "maturity_stage": workflow.get("maturity_stage"),
                "mcp_namespaces": workflow_namespaces(workflow),
                "minimum_retention_days": telemetry_row.get("minimum_retention_days", 400),
                "public_path": workflow.get("public_path"),
                "receipt_id": telemetry_row.get("receipt_id"),
                "replay_fixture_count": len(replay_rows),
                "required_signal_classes": telemetry_row.get("required_signal_classes", []),
                "soc_default_decision": "soc_hold_for_trace_completion" if telemetry_row.get("decision") != "telemetry_ready" else "soc_no_alert",
                "status": workflow.get("status"),
                "title": workflow.get("title"),
                "workflow_id": workflow_id,
            }
        )
    return overlays


def build_source_artifacts(repo_root: Path, refs: dict[str, Path]) -> dict[str, dict[str, str]]:
    output: dict[str, dict[str, str]] = {}
    for key, ref in sorted(refs.items()):
        path = resolve(repo_root, ref)
        output[key] = {
            "path": normalize_path(ref),
            "sha256": sha256_file(path),
        }
    return output


def build_summary(rules: list[dict[str, Any]], overlays: list[dict[str, Any]], failures: list[str]) -> dict[str, Any]:
    severities = Counter(str(rule.get("severity")) for rule in rules)
    decisions = Counter(str(rule.get("decision")) for rule in rules)
    return {
        "decision_counts": dict(sorted(decisions.items())),
        "failure_count": len(failures),
        "max_rules_per_workflow": max((len(row.get("detection_rule_ids", [])) for row in overlays), default=0),
        "rule_count": len(rules),
        "severity_counts": dict(sorted(severities.items())),
        "siem_target_count": 3,
        "workflow_count": len(overlays),
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
    telemetry = telemetry_workflow_by_id(source_payloads["agentic_telemetry_contract"])
    replay = replay_by_workflow(source_payloads["agentic_red_team_replay_harness"])
    rules = build_detection_rules(profile)
    overlays = build_workflow_overlays(
        workflows=workflows,
        telemetry=telemetry,
        replay=replay,
        rules=rules,
    )
    return {
        "commercialization_path": profile.get("commercialization_path", {}),
        "detection_contract": profile.get("detection_contract", {}),
        "detection_rules": rules,
        "detection_summary": build_summary(rules, overlays, failures),
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "evaluator_contract": {
            "default_decision": "soc_no_alert",
            "decision_order": profile.get("detection_contract", {}).get("decision_order", []),
            "missing_trace_decision": "soc_hold_for_trace_completion",
            "prohibited_field_response": profile.get("detection_contract", {}).get("prohibited_field_response"),
        },
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "The open pack provides portable detection logic, not a guarantee that a customer's collector emits every required attribute.",
                "treatment": "Use the Agentic Telemetry Contract and this SOC pack together during SIEM onboarding."
            },
            {
                "risk": "Query templates require field mapping before they are production-ready in any specific SIEM.",
                "treatment": "Bind SecurityRecipes field names to tenant collector schemas and keep raw prompt/tool payload capture disabled by default."
            },
            {
                "risk": "Agentic attack chains evolve quickly as MCP servers, browser agents, and model capabilities change.",
                "treatment": "Regenerate the pack after source-freshness or threat-radar changes and replay red-team fixtures before rollout."
            }
        ],
        "schema_version": PACK_SCHEMA_VERSION,
        "selected_feature": {
            "id": "agentic-soc-detection-pack",
            "implementation": [
                "SOC detection profile under data/assurance.",
                "Deterministic generator under scripts.",
                "Runtime evaluator for SOC alert/no-alert decisions.",
                "Generated SIEM-ready evidence pack under data/evidence.",
                "Human-readable docs page and MCP tool exposure."
            ],
            "reason": "Enterprise buyers need agentic AI controls that land inside SOC operations, not only docs or standalone JSON evidence."
        },
        "siem_targets": profile.get("siem_targets", []),
        "source_artifacts": source_artifacts,
        "standards_alignment": profile.get("standards_alignment", []),
        "workflow_detection_overlays": overlays,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--telemetry-contract", type=Path, default=DEFAULT_TELEMETRY_CONTRACT)
    parser.add_argument("--incident-response-pack", type=Path, default=DEFAULT_INCIDENT_RESPONSE_PACK)
    parser.add_argument("--threat-radar", type=Path, default=DEFAULT_THREAT_RADAR)
    parser.add_argument("--red-team-replay-harness", type=Path, default=DEFAULT_REPLAY_HARNESS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in SOC detection pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    refs = {
        "agentic_incident_response_pack": args.incident_response_pack,
        "agentic_red_team_replay_harness": args.red_team_replay_harness,
        "agentic_soc_detection_profile": args.profile,
        "agentic_telemetry_contract": args.telemetry_contract,
        "agentic_threat_radar": args.threat_radar,
        "workflow_manifest": args.manifest,
    }
    paths = {key: resolve(repo_root, ref) for key, ref in refs.items()}
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(paths["agentic_soc_detection_profile"])
        source_payloads = {
            key: load_json(path)
            for key, path in paths.items()
            if key != "agentic_soc_detection_profile"
        }
        failures = [*validate_profile(profile), *validate_sources(source_payloads)]
        pack = build_pack(
            profile=profile,
            source_payloads=source_payloads,
            source_artifacts=build_source_artifacts(repo_root, refs),
            generated_at=args.generated_at,
            failures=failures,
        )
    except SocDetectionError as exc:
        print(f"agentic SOC detection pack generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("agentic SOC detection pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_agentic_soc_detection_pack.py", file=sys.stderr)
            return 1
        if current_text != rendered:
            print(f"{output_path} is stale; run scripts/generate_agentic_soc_detection_pack.py", file=sys.stderr)
            return 1
        print(f"Validated agentic SOC detection pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated agentic SOC detection pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated agentic SOC detection pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
