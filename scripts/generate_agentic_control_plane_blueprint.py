#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic control plane blueprint.

The blueprint is the acquisition- and enterprise-architecture layer for
SecurityRecipes. It joins the existing generated evidence packs into one
MCP-readable artifact that explains the product architecture, standards
alignment, buyer diligence questions, and commercialization path for the
"secure context layer for agentic AI" thesis.
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
DEFAULT_PROFILE = Path("data/assurance/agentic-control-plane-blueprint.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-control-plane-blueprint.json")


class ControlPlaneBlueprintError(RuntimeError):
    """Raised when the control plane blueprint cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ControlPlaneBlueprintError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ControlPlaneBlueprintError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ControlPlaneBlueprintError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ControlPlaneBlueprintError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ControlPlaneBlueprintError(f"{label} must be an object")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def validate_profile(profile: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 100, failures, "profile intent must explain the product goal")

    standards = as_list(profile.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 7, failures, "standards_alignment must include current agentic AI references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in standard_ids, failures, f"standards_alignment[{idx}].id duplicates {standard_id}")
        standard_ids.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 60, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(profile.get("control_plane_contract"), "control_plane_contract")
    require(
        contract.get("default_state") == "untrusted_until_registered_measured_and_policy_bound",
        failures,
        "control_plane_contract.default_state must fail closed",
    )
    require(len(as_list(contract.get("board_level_success_criteria"), "control_plane_contract.board_level_success_criteria")) >= 5, failures, "board success criteria are required")
    require(len(as_list(contract.get("required_runtime_fields"), "control_plane_contract.required_runtime_fields")) >= 12, failures, "runtime trace fields are required")

    source_catalog = as_list(profile.get("source_pack_catalog"), "source_pack_catalog")
    minimum_source_packs = int(contract.get("minimum_source_packs") or 0)
    require(len(source_catalog) >= minimum_source_packs, failures, "source_pack_catalog is below the minimum source pack count")
    source_ids: set[str] = set()
    for idx, source in enumerate(source_catalog):
        item = as_dict(source, f"source_pack_catalog[{idx}]")
        source_id = str(item.get("id", "")).strip()
        path = Path(str(item.get("path", "")))
        require(bool(source_id), failures, f"source_pack_catalog[{idx}].id is required")
        require(source_id not in source_ids, failures, f"source_pack_catalog[{idx}].id duplicates {source_id}")
        source_ids.add(source_id)
        require(str(item.get("title", "")).strip(), failures, f"{source_id}: title is required")
        require(bool(str(item.get("path", "")).strip()), failures, f"{source_id}: path is required")
        require(resolve(repo_root, path).exists(), failures, f"{source_id}: path does not exist: {path}")

    layers = as_list(profile.get("layers"), "layers")
    minimum_layers = int(contract.get("minimum_layers") or 0)
    require(len(layers) >= minimum_layers, failures, "layers are below the minimum layer count")
    layer_ids: set[str] = set()
    mcp_tools: set[str] = set()
    for idx, layer in enumerate(layers):
        item = as_dict(layer, f"layers[{idx}]")
        layer_id = str(item.get("id", "")).strip()
        layer_ids.add(layer_id)
        require(bool(layer_id), failures, f"layers[{idx}].id is required")
        require(str(item.get("title", "")).strip(), failures, f"{layer_id}: title is required")
        require(len(str(item.get("proof_question", ""))) >= 50, failures, f"{layer_id}: proof_question must be specific")
        layer_sources = {str(source_id) for source_id in as_list(item.get("source_pack_ids"), f"{layer_id}.source_pack_ids")}
        missing_sources = sorted(layer_sources - source_ids)
        require(not missing_sources, failures, f"{layer_id}: unknown source_pack_ids: {missing_sources}")
        layer_tools = {str(tool) for tool in as_list(item.get("mcp_tools"), f"{layer_id}.mcp_tools")}
        require(len(layer_tools) >= 3, failures, f"{layer_id}: at least three MCP tools are required")
        mcp_tools.update(layer_tools)
        require(str(item.get("premium_path", "")).strip(), failures, f"{layer_id}: premium_path is required")
        require(str(item.get("exit_value", "")).strip(), failures, f"{layer_id}: exit_value is required")

    require(len(mcp_tools) >= int(contract.get("minimum_mcp_tools") or 0), failures, "MCP tool count is below the control-plane minimum")
    require(len(layer_ids) == len(layers), failures, "layer IDs must be unique")

    questions = as_list(profile.get("buyer_due_diligence_questions"), "buyer_due_diligence_questions")
    require(len(questions) >= 5, failures, "buyer diligence questions are required")
    for idx, question in enumerate(questions):
        item = as_dict(question, f"buyer_due_diligence_questions[{idx}]")
        question_layers = {str(layer_id) for layer_id in as_list(item.get("layer_ids"), f"buyer_due_diligence_questions[{idx}].layer_ids")}
        missing_layers = sorted(question_layers - layer_ids)
        require(not missing_layers, failures, f"{item.get('id', idx)}: unknown layer_ids: {missing_layers}")

    adoption = as_dict(profile.get("enterprise_adoption_packet"), "enterprise_adoption_packet")
    require(str(adoption.get("board_level_claim", "")).strip(), failures, "enterprise_adoption_packet.board_level_claim is required")
    require(str(adoption.get("sales_motion", "")).strip(), failures, "enterprise_adoption_packet.sales_motion is required")

    return failures


def load_source_packs(profile: dict[str, Any], repo_root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    packs: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for source in as_list(profile.get("source_pack_catalog"), "source_pack_catalog"):
        item = as_dict(source, "source_pack")
        source_id = str(item.get("id"))
        source_path = resolve(repo_root, Path(str(item.get("path"))))
        try:
            packs[source_id] = load_json(source_path)
        except ControlPlaneBlueprintError as exc:
            failures.append(f"{source_id}: {exc}")
    return packs, failures


def source_pack_rows(profile: dict[str, Any], packs: dict[str, dict[str, Any]], repo_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in as_list(profile.get("source_pack_catalog"), "source_pack_catalog"):
        item = as_dict(source, "source_pack")
        source_id = str(item.get("id"))
        rel_path = Path(str(item.get("path")))
        path = resolve(repo_root, rel_path)
        pack = packs.get(source_id, {})
        pack_failures = pack.get("failures") if isinstance(pack.get("failures"), list) else []
        rows.append(
            {
                "available": path.exists(),
                "failure_count": len(pack_failures),
                "id": source_id,
                "path": normalize_path(rel_path),
                "schema_version": pack.get("schema_version"),
                "sha256": sha256_file(path) if path.exists() else None,
                "title": item.get("title"),
            }
        )
    return rows


def workflow_summary(manifest: dict[str, Any], readiness: dict[str, Any], bom: dict[str, Any]) -> dict[str, Any]:
    workflows = [workflow for workflow in manifest.get("workflows", []) if isinstance(workflow, dict)]
    status_counts = Counter(str(workflow.get("status")) for workflow in workflows)
    maturity_counts = Counter(str(workflow.get("maturity_stage")) for workflow in workflows)
    agent_classes = sorted(
        {
            str(agent)
            for workflow in workflows
            for agent in workflow.get("default_agents", [])
        }
    )
    namespaces = sorted(
        {
            str(context.get("namespace"))
            for workflow in workflows
            for context in workflow.get("mcp_context", [])
            if isinstance(context, dict) and context.get("namespace")
        }
    )
    readiness_summary = readiness.get("readiness_summary", {}) if isinstance(readiness, dict) else {}
    bom_summary = bom.get("bom_summary", {}) if isinstance(bom, dict) else {}
    return {
        "active_workflow_count": status_counts.get("active", 0),
        "agent_class_count": len(agent_classes),
        "agent_classes": agent_classes,
        "bom_component_counts": bom_summary.get("component_counts", {}),
        "maturity_counts": dict(sorted(maturity_counts.items())),
        "mcp_namespace_count": len(namespaces),
        "readiness_decision_counts": readiness_summary.get("decision_counts", {}),
        "status_counts": dict(sorted(status_counts.items())),
        "workflow_count": len(workflows),
    }


def pack_summary(packs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "a2a_agent_card_trust": packs.get("a2a_agent_card_trust_profile", {}).get("agent_card_trust_summary"),
        "agentic_assurance": packs.get("agentic_assurance_pack", {}).get("assurance_summary"),
        "agentic_catastrophic_risk_annex": packs.get("agentic_catastrophic_risk_annex", {}).get("annex_summary"),
        "agent_handoff_boundary": packs.get("agent_handoff_boundary_pack", {}).get("handoff_boundary_summary"),
        "agentic_measurement": packs.get("agentic_measurement_probe_pack", {}).get("measurement_probe_summary"),
        "agentic_system_bom": packs.get("agentic_system_bom", {}).get("bom_summary"),
        "agentic_standards_crosswalk": packs.get("agentic_standards_crosswalk", {}).get("crosswalk_summary"),
        "agentic_threat_radar": packs.get("agentic_threat_radar", {}).get("threat_radar_summary"),
        "authorization_conformance": packs.get("mcp_authorization_conformance_pack", {}).get("authorization_summary"),
        "connector_trust": packs.get("mcp_connector_trust_pack", {}).get("connector_trust_summary"),
        "context_attestation": packs.get("secure_context_attestation_pack", {}).get("attestation_summary"),
        "context_egress": packs.get("context_egress_boundary_pack", {}).get("egress_boundary_summary"),
        "context_poisoning": packs.get("context_poisoning_guard_pack", {}).get("guard_summary"),
        "context_trust": packs.get("secure_context_trust_pack", {}).get("context_trust_summary"),
        "readiness": packs.get("agentic_readiness_scorecard", {}).get("readiness_summary"),
    }


def layer_rows(profile: dict[str, Any], source_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    source_by_id = {str(row.get("id")): row for row in source_rows}
    rows: list[dict[str, Any]] = []
    for layer in as_list(profile.get("layers"), "layers"):
        item = as_dict(layer, "layer")
        source_ids = [str(source_id) for source_id in item.get("source_pack_ids", [])]
        layer_sources = [source_by_id[source_id] for source_id in source_ids if source_id in source_by_id]
        ready_sources = [
            source
            for source in layer_sources
            if bool(source.get("available")) and int(source.get("failure_count") or 0) == 0
        ]
        status = "ready" if len(ready_sources) == len(source_ids) else "needs_attention"
        rows.append(
            {
                "evidence_coverage_score": round((len(ready_sources) / max(len(source_ids), 1)) * 100, 2),
                "evidence_paths": [source.get("path") for source in layer_sources],
                "exit_value": item.get("exit_value"),
                "id": item.get("id"),
                "mcp_tool_count": len(item.get("mcp_tools", [])),
                "mcp_tools": item.get("mcp_tools", []),
                "premium_path": item.get("premium_path"),
                "proof_question": item.get("proof_question"),
                "source_pack_count": len(source_ids),
                "source_pack_ids": source_ids,
                "status": status,
                "title": item.get("title"),
            }
        )
    return rows


def due_diligence_matrix(profile: dict[str, Any], layers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    layers_by_id = {str(layer.get("id")): layer for layer in layers}
    rows: list[dict[str, Any]] = []
    for question in as_list(profile.get("buyer_due_diligence_questions"), "buyer_due_diligence_questions"):
        item = as_dict(question, "buyer_due_diligence_question")
        question_layers = [
            layers_by_id[str(layer_id)]
            for layer_id in item.get("layer_ids", [])
            if str(layer_id) in layers_by_id
        ]
        evidence_paths = sorted(
            {
                str(path)
                for layer in question_layers
                for path in layer.get("evidence_paths", [])
                if path
            }
        )
        mcp_tools = sorted(
            {
                str(tool)
                for layer in question_layers
                for tool in layer.get("mcp_tools", [])
            }
        )
        rows.append(
            {
                "evidence_paths": evidence_paths,
                "id": item.get("id"),
                "layer_ids": item.get("layer_ids", []),
                "mcp_tools": mcp_tools,
                "question": item.get("question"),
            }
        )
    return rows


def readiness_summary(
    layers: list[dict[str, Any]],
    source_rows: list[dict[str, Any]],
    packs: dict[str, dict[str, Any]],
    manifest_summary: dict[str, Any],
) -> dict[str, Any]:
    ready_layers = [layer for layer in layers if layer.get("status") == "ready"]
    source_ready = [source for source in source_rows if source.get("available") and int(source.get("failure_count") or 0) == 0]
    mcp_tools = sorted({str(tool) for layer in layers for tool in layer.get("mcp_tools", [])})
    readiness = packs.get("agentic_readiness_scorecard", {}).get("readiness_summary", {})
    active_workflows = int(manifest_summary.get("active_workflow_count") or 0)
    scale_ready = int(readiness.get("scale_ready_workflow_count") or 0)
    layer_component = len(ready_layers) / max(len(layers), 1)
    source_component = len(source_ready) / max(len(source_rows), 1)
    workflow_component = scale_ready / max(active_workflows, 1)
    score = round((layer_component * 45) + (source_component * 35) + (workflow_component * 20), 2)
    return {
        "active_workflow_count": active_workflows,
        "blueprint_score": score,
        "distinct_mcp_tool_count": len(mcp_tools),
        "ready_layer_count": len(ready_layers),
        "ready_source_pack_count": len(source_ready),
        "scale_ready_workflow_count": scale_ready,
        "source_pack_count": len(source_rows),
        "status": "acquisition_diligence_ready" if score >= 90 else "needs_evidence_before_diligence",
        "total_layer_count": len(layers),
    }


def build_pack(
    *,
    profile: dict[str, Any],
    profile_path: Path,
    profile_ref: Path,
    repo_root: Path,
    generated_at: str | None,
    failures: list[str],
    packs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    sources = source_pack_rows(profile, packs, repo_root)
    layers = layer_rows(profile, sources)
    manifest = packs.get("workflow_manifest", {})
    readiness = packs.get("agentic_readiness_scorecard", {})
    bom = packs.get("agentic_system_bom", {})
    manifest_summary = workflow_summary(manifest, readiness, bom)
    return {
        "acquisition_readiness": readiness_summary(layers, sources, packs, manifest_summary),
        "buyer_due_diligence_matrix": due_diligence_matrix(profile, layers),
        "commercialization_path": profile.get("commercialization_path", {}),
        "control_plane_contract": profile.get("control_plane_contract", {}),
        "control_plane_summary": manifest_summary,
        "enterprise_adoption_packet": profile.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "layers": layers,
        "pack_summaries": pack_summary(packs),
        "positioning": profile.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "The blueprint proves the open reference architecture, not live customer enforcement.",
                "treatment": "Bind generated packs to tenant MCP gateway logs, identity-provider records, source-host reviews, and runtime receipts before production attestation."
            },
            {
                "risk": "Agentic standards and MCP authorization guidance are still evolving.",
                "treatment": "Review the source model quarterly and regenerate the blueprint when NIST, OWASP, MCP, CSA, CISA, or model-lab guidance changes."
            },
            {
                "risk": "A ready architecture can still fail if connectors, models, prompts, or customer data drift after approval.",
                "treatment": "Use measurement probes, red-team replay, source-hash checks, and readiness regeneration as promotion gates."
            }
        ],
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": {
            "blueprint_profile": {
                "path": normalize_path(profile_ref),
                "sha256": sha256_file(profile_path),
            },
            "source_packs": sources,
        },
        "standards_alignment": profile.get("standards_alignment", []),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in control plane blueprint is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        failures = validate_profile(profile, repo_root)
        packs, pack_failures = load_source_packs(profile, repo_root)
        failures.extend(pack_failures)
        pack = build_pack(
            profile=profile,
            profile_path=profile_path,
            profile_ref=args.profile,
            repo_root=repo_root,
            generated_at=args.generated_at,
            failures=failures,
            packs=packs,
        )
    except ControlPlaneBlueprintError as exc:
        print(f"agentic control plane blueprint generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)
    if args.check:
        if failures:
            print("agentic control plane blueprint validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(f"{output_path} is stale; run scripts/generate_agentic_control_plane_blueprint.py", file=sys.stderr)
            return 1
        print(f"Validated agentic control plane blueprint: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated agentic control plane blueprint with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agentic control plane blueprint: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
