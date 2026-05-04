#!/usr/bin/env python3
"""Generate the SecurityRecipes agentic standards crosswalk.

The crosswalk maps current agentic AI security standards and frontier-lab
guidance to SecurityRecipes capabilities, evidence paths, and MCP tools.
The output is deterministic so CI can detect stale standards evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


CROSSWALK_SCHEMA_VERSION = "1.0"
DEFAULT_PROFILE = Path("data/assurance/agentic-standards-crosswalk.json")
DEFAULT_OUTPUT = Path("data/evidence/agentic-standards-crosswalk.json")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]+$")
VALID_STATUS = {"implemented", "planned", "recommended_next", "watch"}


class StandardsCrosswalkError(RuntimeError):
    """Raised when the standards crosswalk cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise StandardsCrosswalkError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise StandardsCrosswalkError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise StandardsCrosswalkError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise StandardsCrosswalkError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StandardsCrosswalkError(f"{label} must be an object")
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


def output_path_allowed(path: str, output_ref: Path) -> bool:
    return Path(path).as_posix() == output_ref.as_posix()


def validate_profile(profile: dict[str, Any], repo_root: Path, output_ref: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == CROSSWALK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 100, failures, "profile intent must explain the standards goal")

    contract = as_dict(profile.get("control_plane_contract"), "control_plane_contract")
    require(
        contract.get("default_state") == "not_enterprise_ready_until_each_referenced_standard_control_has_generated_evidence",
        failures,
        "control_plane_contract.default_state must fail closed",
    )

    source_refs = as_list(profile.get("source_references"), "source_references")
    require(len(source_refs) >= 10, failures, "source_references must include current standards and lab guidance")
    source_ids: set[str] = set()
    source_classes: set[str] = set()
    for idx, source in enumerate(source_refs):
        item = as_dict(source, f"source_references[{idx}]")
        source_id = str(item.get("id", "")).strip()
        require(bool(ID_RE.match(source_id)), failures, f"source_references[{idx}].id is invalid")
        require(source_id not in source_ids, failures, f"{source_id}: duplicate source id")
        source_ids.add(source_id)
        source_classes.add(str(item.get("source_class", "")).strip())
        require(str(item.get("url", "")).startswith("https://"), failures, f"{source_id}: url must be https")
        require(str(item.get("publisher", "")).strip(), failures, f"{source_id}: publisher is required")
        require(str(item.get("published", "")).strip(), failures, f"{source_id}: published is required")
        require(len(str(item.get("why_it_matters", ""))) >= 50, failures, f"{source_id}: why_it_matters must be specific")

    for required_class in {"industry_standard", "government_framework", "protocol_specification", "frontier_lab_guidance"}:
        require(required_class in source_classes, failures, f"source_references must include {required_class}")

    capabilities = as_list(profile.get("capabilities"), "capabilities")
    minimum_capabilities = int(contract.get("minimum_capabilities") or 0)
    require(len(capabilities) >= minimum_capabilities, failures, "capability count below crosswalk minimum")
    capability_ids: set[str] = set()
    for idx, capability in enumerate(capabilities):
        item = as_dict(capability, f"capabilities[{idx}]")
        capability_id = str(item.get("id", "")).strip()
        require(bool(ID_RE.match(capability_id)), failures, f"capabilities[{idx}].id is invalid")
        require(capability_id not in capability_ids, failures, f"{capability_id}: duplicate capability id")
        capability_ids.add(capability_id)
        require(str(item.get("status")) in VALID_STATUS, failures, f"{capability_id}: status is invalid")
        require(str(item.get("title", "")).strip(), failures, f"{capability_id}: title is required")
        require(len(str(item.get("commercial_value", ""))) >= 50, failures, f"{capability_id}: commercial_value must be specific")
        evidence_paths = as_list(item.get("evidence_paths"), f"{capability_id}.evidence_paths")
        require(bool(evidence_paths), failures, f"{capability_id}: evidence_paths are required")
        for raw_path in evidence_paths:
            path = str(raw_path)
            if output_path_allowed(path, output_ref):
                continue
            require(resolve(repo_root, Path(path)).exists(), failures, f"{capability_id}: evidence path does not exist: {path}")

    for capability_id in as_list(contract.get("required_capability_ids"), "control_plane_contract.required_capability_ids"):
        require(str(capability_id) in capability_ids, failures, f"required capability is missing: {capability_id}")

    standards = as_list(profile.get("standards"), "standards")
    minimum_standards = int(contract.get("minimum_standards") or 0)
    require(len(standards) >= minimum_standards, failures, "standard count below crosswalk minimum")
    standard_ids: set[str] = set()
    total_controls = 0
    covered_capabilities: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(ID_RE.match(standard_id)), failures, f"standards[{idx}].id is invalid")
        require(standard_id not in standard_ids, failures, f"{standard_id}: duplicate standard id")
        standard_ids.add(standard_id)
        require(str(item.get("title", "")).strip(), failures, f"{standard_id}: title is required")
        require(len(str(item.get("buyer_question", ""))) >= 60, failures, f"{standard_id}: buyer_question must be specific")
        for source_id in as_list(item.get("source_ids"), f"{standard_id}.source_ids"):
            require(str(source_id) in source_ids, failures, f"{standard_id}: unknown source_id {source_id}")

        controls = as_list(item.get("controls"), f"{standard_id}.controls")
        total_controls += len(controls)
        require(len(controls) >= int(item.get("minimum_required_controls") or 0), failures, f"{standard_id}: controls below minimum_required_controls")
        control_ids: set[str] = set()
        for control_idx, control in enumerate(controls):
            control_item = as_dict(control, f"{standard_id}.controls[{control_idx}]")
            control_id = str(control_item.get("id", "")).strip()
            require(bool(ID_RE.match(control_id)), failures, f"{standard_id}: control id is invalid: {control_id}")
            require(control_id not in control_ids, failures, f"{standard_id}: duplicate control id {control_id}")
            control_ids.add(control_id)
            require(len(str(control_item.get("objective", ""))) >= 50, failures, f"{standard_id}.{control_id}: objective must be specific")
            require(len(str(control_item.get("diligence_question", ""))) >= 45, failures, f"{standard_id}.{control_id}: diligence_question must be specific")
            require(len(str(control_item.get("evidence_expectation", ""))) >= 70, failures, f"{standard_id}.{control_id}: evidence_expectation must be specific")
            required_capabilities = as_list(
                control_item.get("required_capability_ids"),
                f"{standard_id}.{control_id}.required_capability_ids",
            )
            require(len(required_capabilities) >= 3, failures, f"{standard_id}.{control_id}: at least three capabilities are required")
            for capability_id in required_capabilities:
                require(str(capability_id) in capability_ids, failures, f"{standard_id}.{control_id}: unknown capability {capability_id}")
                covered_capabilities.add(str(capability_id))

    require(total_controls >= int(contract.get("minimum_controls") or 0), failures, "standards controls below crosswalk minimum")
    missing_required_coverage = sorted(set(contract.get("required_capability_ids", [])) - covered_capabilities)
    require(not missing_required_coverage, failures, f"required capabilities are not covered by controls: {missing_required_coverage}")

    buyer_views = as_list(profile.get("buyer_views"), "buyer_views")
    require(len(buyer_views) >= 3, failures, "buyer_views must include procurement, platform, and diligence views")
    for idx, buyer_view in enumerate(buyer_views):
        item = as_dict(buyer_view, f"buyer_views[{idx}]")
        view_id = str(item.get("id", "")).strip()
        require(bool(ID_RE.match(view_id)), failures, f"buyer_views[{idx}].id is invalid")
        for standard_id in as_list(item.get("required_standard_ids"), f"{view_id}.required_standard_ids"):
            require(str(standard_id) in standard_ids, failures, f"{view_id}: unknown standard id {standard_id}")
        require(len(str(item.get("answer_contract", ""))) >= 70, failures, f"{view_id}: answer_contract must be specific")

    return failures


def source_by_id(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(source.get("id")): source
        for source in profile.get("source_references", [])
        if isinstance(source, dict) and source.get("id")
    }


def capability_by_id(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(capability.get("id")): capability
        for capability in profile.get("capabilities", [])
        if isinstance(capability, dict) and capability.get("id")
    }


def source_preview(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": source.get("id"),
        "name": source.get("name"),
        "published": source.get("published"),
        "publisher": source.get("publisher"),
        "source_class": source.get("source_class"),
        "url": source.get("url"),
    }


def capability_preview(capability: dict[str, Any]) -> dict[str, Any]:
    return {
        "commercial_value": capability.get("commercial_value"),
        "evidence_paths": capability.get("evidence_paths", []),
        "id": capability.get("id"),
        "mcp_tools": capability.get("mcp_tools", []),
        "status": capability.get("status"),
        "title": capability.get("title"),
    }


def build_controls(profile: dict[str, Any]) -> list[dict[str, Any]]:
    capabilities = capability_by_id(profile)
    sources = source_by_id(profile)
    rows: list[dict[str, Any]] = []
    for standard in as_list(profile.get("standards"), "standards"):
        item = as_dict(standard, "standard")
        standard_source_previews = [
            source_preview(sources[str(source_id)])
            for source_id in item.get("source_ids", [])
            if str(source_id) in sources
        ]
        for control in as_list(item.get("controls"), f"{item.get('id')}.controls"):
            control_item = as_dict(control, "control")
            capability_ids = [str(capability_id) for capability_id in control_item.get("required_capability_ids", [])]
            control_capabilities = [
                capability_preview(capabilities[capability_id])
                for capability_id in capability_ids
                if capability_id in capabilities
            ]
            evidence_paths = sorted(
                {
                    str(path)
                    for capability in control_capabilities
                    for path in capability.get("evidence_paths", [])
                }
            )
            mcp_tools = sorted(
                {
                    str(tool)
                    for capability in control_capabilities
                    for tool in capability.get("mcp_tools", [])
                }
            )
            rows.append(
                {
                    "capabilities": control_capabilities,
                    "diligence_question": control_item.get("diligence_question"),
                    "evidence_expectation": control_item.get("evidence_expectation"),
                    "evidence_paths": evidence_paths,
                    "id": control_item.get("id"),
                    "mcp_tools": mcp_tools,
                    "objective": control_item.get("objective"),
                    "required_capability_ids": capability_ids,
                    "source_ids": item.get("source_ids", []),
                    "sources": standard_source_previews,
                    "standard_id": item.get("id"),
                    "standard_title": item.get("title"),
                    "status": "ready" if len(control_capabilities) == len(capability_ids) and evidence_paths else "needs_attention",
                    "title": control_item.get("title"),
                }
            )
    return rows


def build_standards(profile: dict[str, Any], controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    controls_by_standard: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in controls:
        controls_by_standard[str(control.get("standard_id"))].append(control)

    sources = source_by_id(profile)
    rows: list[dict[str, Any]] = []
    for standard in as_list(profile.get("standards"), "standards"):
        item = as_dict(standard, "standard")
        standard_id = str(item.get("id"))
        standard_controls = controls_by_standard[standard_id]
        ready_controls = [control for control in standard_controls if control.get("status") == "ready"]
        capability_ids = sorted(
            {
                str(capability_id)
                for control in standard_controls
                for capability_id in control.get("required_capability_ids", [])
            }
        )
        mcp_tools = sorted(
            {
                str(tool)
                for control in standard_controls
                for tool in control.get("mcp_tools", [])
            }
        )
        rows.append(
            {
                "buyer_question": item.get("buyer_question"),
                "capability_count": len(capability_ids),
                "control_count": len(standard_controls),
                "coverage_score": round((len(ready_controls) / max(len(standard_controls), 1)) * 100, 2),
                "id": standard_id,
                "kind": item.get("kind"),
                "mcp_tools": mcp_tools,
                "ready_control_count": len(ready_controls),
                "source_ids": item.get("source_ids", []),
                "sources": [
                    source_preview(sources[str(source_id)])
                    for source_id in item.get("source_ids", [])
                    if str(source_id) in sources
                ],
                "status": "ready" if len(ready_controls) == len(standard_controls) else "needs_attention",
                "title": item.get("title"),
            }
        )
    return rows


def build_capability_coverage(controls: list[dict[str, Any]], capabilities: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    coverage: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in controls:
        for capability_id in control.get("required_capability_ids", []):
            coverage[str(capability_id)].append(control)

    rows: list[dict[str, Any]] = []
    for capability_id in sorted(capabilities):
        mapped_controls = coverage.get(capability_id, [])
        capability = capabilities[capability_id]
        rows.append(
            {
                "capability": capability_preview(capability),
                "capability_id": capability_id,
                "control_count": len(mapped_controls),
                "standard_count": len({str(control.get("standard_id")) for control in mapped_controls}),
                "control_ids": [f"{control.get('standard_id')}::{control.get('id')}" for control in mapped_controls],
                "status": "covered" if mapped_controls else "unmapped",
            }
        )
    return rows


def build_buyer_views(profile: dict[str, Any], standards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    standards_by_id = {str(standard.get("id")): standard for standard in standards}
    rows: list[dict[str, Any]] = []
    for view in as_list(profile.get("buyer_views"), "buyer_views"):
        item = as_dict(view, "buyer_view")
        selected = [
            standards_by_id[str(standard_id)]
            for standard_id in item.get("required_standard_ids", [])
            if str(standard_id) in standards_by_id
        ]
        rows.append(
            {
                "answer_contract": item.get("answer_contract"),
                "id": item.get("id"),
                "question": item.get("question"),
                "required_standard_ids": item.get("required_standard_ids", []),
                "standards": selected,
                "title": item.get("title"),
            }
        )
    return rows


def source_artifacts(profile_path: Path, profile_ref: Path, repo_root: Path, output_ref: Path, profile: dict[str, Any]) -> dict[str, Any]:
    artifacts: dict[str, dict[str, Any]] = {}
    for capability in profile.get("capabilities", []) or []:
        if not isinstance(capability, dict):
            continue
        for raw_path in capability.get("evidence_paths", []) or []:
            path = str(raw_path)
            if output_path_allowed(path, output_ref):
                continue
            resolved = resolve(repo_root, Path(path))
            if resolved.exists() and resolved.is_file():
                artifacts[path] = {"path": path, "sha256": sha256_file(resolved)}
    return {
        "agentic_standards_crosswalk_profile": {
            "path": normalize_path(profile_ref),
            "sha256": sha256_file(profile_path),
        },
        "capability_evidence": [artifacts[path] for path in sorted(artifacts)],
    }


def build_summary(
    profile: dict[str, Any],
    standards: list[dict[str, Any]],
    controls: list[dict[str, Any]],
    coverage: list[dict[str, Any]],
    failures: list[str],
) -> dict[str, Any]:
    source_classes = Counter(str(source.get("source_class")) for source in profile.get("source_references", []) if isinstance(source, dict))
    standard_status = Counter(str(standard.get("status")) for standard in standards)
    control_status = Counter(str(control.get("status")) for control in controls)
    covered_capabilities = [row for row in coverage if row.get("status") == "covered"]
    mcp_tools = sorted({str(tool) for control in controls for tool in control.get("mcp_tools", [])})
    return {
        "capability_count": len(coverage),
        "control_count": len(controls),
        "control_status_counts": dict(sorted(control_status.items())),
        "covered_capability_count": len(covered_capabilities),
        "distinct_mcp_tool_count": len(mcp_tools),
        "failure_count": len(failures),
        "source_class_counts": dict(sorted(source_classes.items())),
        "source_reference_count": len(profile.get("source_references", []) or []),
        "standard_count": len(standards),
        "standard_status_counts": dict(sorted(standard_status.items())),
        "status": "standards_crosswalk_ready" if not failures and control_status.get("needs_attention", 0) == 0 else "needs_attention_before_enterprise_review",
    }


def build_pack(
    *,
    profile: dict[str, Any],
    profile_path: Path,
    profile_ref: Path,
    output_ref: Path,
    repo_root: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    controls = build_controls(profile)
    standards = build_standards(profile, controls)
    capabilities = capability_by_id(profile)
    coverage = build_capability_coverage(controls, capabilities)
    return {
        "buyer_views": build_buyer_views(profile, standards),
        "capability_coverage": coverage,
        "commercialization_path": {
            "open_layer": "Publish the crosswalk as open evidence so practitioners can compare SecurityRecipes to current agentic AI security guidance.",
            "enterprise_layer": "Sell hosted standards drift monitoring, customer-private evidence mapping, procurement exports, and MCP gateway conformance reporting.",
            "acquirer_value": "A strategic acquirer gets a standards-backed control map that can be attached to agent hosts, MCP gateways, and enterprise AI trust centers."
        },
        "control_plane_contract": profile.get("control_plane_contract", {}),
        "controls": controls,
        "crosswalk_summary": build_summary(profile, standards, controls, coverage, failures),
        "enterprise_adoption_packet": {
            "board_level_claim": "SecurityRecipes maps current agentic AI standards to generated evidence and MCP tools, making the secure context layer inspectable by platform teams and buyers.",
            "default_questions_answered": [
                "Which current standards and guidance are tracked?",
                "Which SecurityRecipes capabilities support each control?",
                "Which MCP tools expose the evidence?",
                "Which source files and generated packs prove the mapping?",
                "Which capability gaps would block enterprise review?"
            ],
            "recommended_first_use": "Attach this crosswalk to procurement security review, AI platform architecture review, MCP gateway intake, quarterly standards drift review, and acquisition diligence.",
            "sales_motion": "Lead with open standards coverage, then sell hosted customer-specific evidence mapping, standards drift alerts, conformance APIs, and trust-center exports."
        },
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "positioning": profile.get("positioning", {}),
        "schema_version": CROSSWALK_SCHEMA_VERSION,
        "source_artifacts": source_artifacts(profile_path, profile_ref, repo_root, output_ref, profile),
        "source_references": profile.get("source_references", []),
        "standards": standards,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in standards crosswalk is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    profile_path = resolve(repo_root, args.profile)
    output_path = resolve(repo_root, args.output)

    try:
        profile = load_json(profile_path)
        failures = validate_profile(profile, repo_root, args.output)
        pack = build_pack(
            profile=profile,
            profile_path=profile_path,
            profile_ref=args.profile,
            output_ref=args.output,
            repo_root=repo_root,
            generated_at=args.generated_at,
            failures=failures,
        )
    except StandardsCrosswalkError as exc:
        print(f"agentic standards crosswalk generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)
    if args.check:
        if failures:
            print("agentic standards crosswalk validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_agentic_standards_crosswalk.py", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(f"{output_path} is stale; run scripts/generate_agentic_standards_crosswalk.py", file=sys.stderr)
            return 1
        print(f"Validated agentic standards crosswalk: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")

    if failures:
        print("Generated agentic standards crosswalk with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated agentic standards crosswalk: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
