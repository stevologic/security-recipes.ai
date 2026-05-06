#!/usr/bin/env python3
"""Generate the SecurityRecipes secure context evidence contract.

The contract is the bridge between the open evidence corpus and a hosted
product surface. It defines the evidence object catalog, release channels,
hosted API shape, source-pack hashes, and fail-closed release controls a
buyer would expect before trust-center, design-partner, or acquirer
evidence leaves the repository or a tenant boundary.
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
DEFAULT_PROFILE = Path("data/assurance/secure-context-evidence-contract-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/secure-context-evidence-contract.json")


class EvidenceContractError(RuntimeError):
    """Raised when the secure context evidence contract cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise EvidenceContractError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise EvidenceContractError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise EvidenceContractError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceContractError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceContractError(f"{label} must be a list")
    return value


def normalize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: normalize_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_json(item) for item in value]
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(normalize_json(payload), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def validate_profile(profile: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 100, failures, "profile intent must explain the evidence contract goal")

    contract = as_dict(profile.get("release_contract"), "release_contract")
    require(
        contract.get("default_state") == "hold_release_until_evidence_is_redacted_bound_and_signed",
        failures,
        "release_contract.default_state must fail closed",
    )
    require(len(as_list(contract.get("required_runtime_attributes"), "required_runtime_attributes")) >= 12, failures, "runtime attributes are incomplete")
    require(len(as_list(contract.get("valid_runtime_decisions"), "valid_runtime_decisions")) >= 5, failures, "runtime decisions are incomplete")
    require(len(as_list(contract.get("prohibited_payload_classes"), "prohibited_payload_classes")) >= 6, failures, "prohibited payload classes are incomplete")
    release_controls = {str(item) for item in as_list(contract.get("release_controls"), "release_controls")}
    require(len(release_controls) >= 10, failures, "release controls are incomplete")

    sources = as_list(profile.get("source_references"), "source_references")
    require(len(sources) >= 7, failures, "source_references must include protocol, government, lab, and industry references")
    source_classes: set[str] = set()
    source_ids: set[str] = set()
    for idx, source in enumerate(sources):
        item = as_dict(source, f"source_references[{idx}]")
        source_id = str(item.get("id", "")).strip()
        require(bool(source_id), failures, f"source_references[{idx}].id is required")
        require(source_id not in source_ids, failures, f"{source_id}: duplicate source id")
        source_ids.add(source_id)
        source_classes.add(str(item.get("source_class", "")).strip())
        require(str(item.get("url", "")).startswith("https://"), failures, f"{source_id}: url must be https")
        require(str(item.get("publisher", "")).strip(), failures, f"{source_id}: publisher is required")
        require(str(item.get("published", "")).strip(), failures, f"{source_id}: published is required")
        require(len(str(item.get("why_it_matters", ""))) >= 60, failures, f"{source_id}: why_it_matters must be specific")
    for required_class in {"protocol_specification", "government_framework", "frontier_lab_guidance", "industry_standard"}:
        require(required_class in source_classes, failures, f"source_references must include {required_class}")

    packs = as_list(profile.get("source_pack_index"), "source_pack_index")
    require(len(packs) >= int(contract.get("minimum_source_pack_count") or 0), failures, "source pack count below minimum")
    pack_ids: set[str] = set()
    for idx, pack in enumerate(packs):
        item = as_dict(pack, f"source_pack_index[{idx}]")
        pack_id = str(item.get("id", "")).strip()
        pack_path = Path(str(item.get("path", "")))
        require(bool(pack_id), failures, f"source_pack_index[{idx}].id is required")
        require(pack_id not in pack_ids, failures, f"{pack_id}: duplicate source pack id")
        pack_ids.add(pack_id)
        require(bool(str(item.get("title", "")).strip()), failures, f"{pack_id}: title is required")
        require(bool(str(item.get("category", "")).strip()), failures, f"{pack_id}: category is required")
        require(bool(str(item.get("path", "")).strip()), failures, f"{pack_id}: path is required")
        require(resolve(repo_root, pack_path).exists(), failures, f"{pack_id}: path does not exist: {pack_path}")
        require(bool(as_list(item.get("mcp_tools"), f"{pack_id}.mcp_tools")), failures, f"{pack_id}: mcp_tools are required")

    object_types = as_list(profile.get("evidence_object_types"), "evidence_object_types")
    require(len(object_types) >= int(contract.get("minimum_evidence_object_types") or 0), failures, "evidence object type count below minimum")
    object_ids: set[str] = set()
    for idx, obj in enumerate(object_types):
        item = as_dict(obj, f"evidence_object_types[{idx}]")
        object_id = str(item.get("id", "")).strip()
        object_ids.add(object_id)
        require(bool(object_id), failures, f"evidence_object_types[{idx}].id is required")
        require(len(str(item.get("description", ""))) >= 50, failures, f"{object_id}: description must be specific")
        require(len(as_list(item.get("required_fields"), f"{object_id}.required_fields")) >= 3, failures, f"{object_id}: required_fields are incomplete")
        require(len(str(item.get("redaction_rule", ""))) >= 50, failures, f"{object_id}: redaction_rule must be specific")
        missing_packs = sorted({str(pack_id) for pack_id in item.get("linked_source_pack_ids", []) or []} - pack_ids)
        require(not missing_packs, failures, f"{object_id}: unknown linked_source_pack_ids {missing_packs}")

    channels = as_list(profile.get("release_channels"), "release_channels")
    require(len(channels) >= int(contract.get("minimum_release_channels") or 0), failures, "release channel count below minimum")
    channel_ids: set[str] = set()
    for idx, channel in enumerate(channels):
        item = as_dict(channel, f"release_channels[{idx}]")
        channel_id = str(item.get("id", "")).strip()
        require(bool(channel_id), failures, f"release_channels[{idx}].id is required")
        require(channel_id not in channel_ids, failures, f"{channel_id}: duplicate release channel id")
        channel_ids.add(channel_id)
        controls = {str(control) for control in as_list(item.get("required_controls"), f"{channel_id}.required_controls")}
        require(bool(controls), failures, f"{channel_id}: required_controls are required")
        require(controls <= release_controls, failures, f"{channel_id}: required_controls include unknown controls {sorted(controls - release_controls)}")
        require("no_secret_or_token_payload" in controls, failures, f"{channel_id}: no_secret_or_token_payload is required")
        require(len(str(item.get("commercial_reason", ""))) >= 60, failures, f"{channel_id}: commercial_reason must be specific")

    api_surface = as_dict(profile.get("hosted_api_surface"), "hosted_api_surface")
    endpoints = as_list(api_surface.get("endpoints"), "hosted_api_surface.endpoints")
    require(len(endpoints) >= int(contract.get("minimum_hosted_api_endpoints") or 0), failures, "hosted API endpoint count below minimum")
    endpoint_ids: set[str] = set()
    for idx, endpoint in enumerate(endpoints):
        item = as_dict(endpoint, f"hosted_api_surface.endpoints[{idx}]")
        endpoint_id = str(item.get("id", "")).strip()
        require(bool(endpoint_id), failures, f"hosted_api_surface.endpoints[{idx}].id is required")
        require(endpoint_id not in endpoint_ids, failures, f"{endpoint_id}: duplicate endpoint id")
        endpoint_ids.add(endpoint_id)
        require(str(item.get("path", "")).startswith("/v1/"), failures, f"{endpoint_id}: path must start with /v1/")
        require(str(item.get("method", "")).upper() in {"GET", "POST"}, failures, f"{endpoint_id}: method must be GET or POST")
        missing_objects = sorted({str(object_id) for object_id in item.get("linked_object_type_ids", []) or []} - object_ids)
        missing_packs = sorted({str(pack_id) for pack_id in item.get("linked_source_pack_ids", []) or []} - pack_ids)
        require(not missing_objects, failures, f"{endpoint_id}: unknown linked_object_type_ids {missing_objects}")
        require(not missing_packs, failures, f"{endpoint_id}: unknown linked_source_pack_ids {missing_packs}")
        require(len(str(item.get("purpose", ""))) >= 60, failures, f"{endpoint_id}: purpose must be specific")

    buyer_views = as_list(profile.get("buyer_views"), "buyer_views")
    require(len(buyer_views) >= 4, failures, "buyer_views must include platform, procurement, security, and acquirer views")
    for idx, view in enumerate(buyer_views):
        item = as_dict(view, f"buyer_views[{idx}]")
        view_id = str(item.get("id", "")).strip()
        require(bool(view_id), failures, f"buyer_views[{idx}].id is required")
        missing_channels = sorted({str(channel_id) for channel_id in item.get("required_release_channels", []) or []} - channel_ids)
        require(not missing_channels, failures, f"{view_id}: unknown required_release_channels {missing_channels}")
        require(len(str(item.get("answer_contract", ""))) >= 80, failures, f"{view_id}: answer_contract must be specific")
    return failures


def load_source_packs(profile: dict[str, Any], repo_root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    packs: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for source in as_list(profile.get("source_pack_index"), "source_pack_index"):
        item = as_dict(source, "source_pack_index item")
        pack_id = str(item.get("id"))
        path = resolve(repo_root, Path(str(item.get("path"))))
        try:
            packs[pack_id] = load_json(path)
        except EvidenceContractError as exc:
            failures.append(f"{pack_id}: {exc}")
    return packs, failures


def pack_failure_count(pack: dict[str, Any] | None) -> int:
    if not isinstance(pack, dict):
        return 1
    failures = pack.get("failures")
    if isinstance(failures, list):
        return len(failures)
    failure_count = pack.get("failure_count")
    if isinstance(failure_count, int):
        return failure_count
    return 0


def pack_summary(pack: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(pack, dict):
        return None
    for key, value in pack.items():
        if key.endswith("_summary") and isinstance(value, dict):
            return {"key": key, "value": value}
    for key in ["acquisition_readiness", "commercial_packaging", "trust_center_summary"]:
        value = pack.get(key)
        if isinstance(value, dict):
            return {"key": key, "value": value}
    return None


def build_source_pack_index(
    profile: dict[str, Any],
    packs: dict[str, dict[str, Any]],
    repo_root: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in as_list(profile.get("source_pack_index"), "source_pack_index"):
        item = as_dict(source, "source_pack_index item")
        pack_id = str(item.get("id"))
        ref = Path(str(item.get("path")))
        path = resolve(repo_root, ref)
        pack = packs.get(pack_id)
        failure_count = pack_failure_count(pack)
        rows.append(
            {
                "available": path.exists() and isinstance(pack, dict),
                "category": item.get("category"),
                "failure_count": failure_count,
                "id": pack_id,
                "mcp_tools": item.get("mcp_tools", []),
                "path": normalize_path(ref),
                "required": bool(item.get("required", True)),
                "schema_version": pack.get("schema_version") if isinstance(pack, dict) else None,
                "sha256": sha256_file(path) if path.exists() else None,
                "status": "ready" if path.exists() and failure_count == 0 else "needs_attention",
                "summary": pack_summary(pack),
                "title": item.get("title"),
            }
        )
    return rows


def build_evidence_object_types(profile: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in as_list(profile.get("evidence_object_types"), "evidence_object_types"):
        item = as_dict(obj, "evidence_object_type")
        rows.append(
            {
                **item,
                "object_contract_hash": stable_hash(
                    {
                        "id": item.get("id"),
                        "required_fields": item.get("required_fields", []),
                        "redaction_rule": item.get("redaction_rule"),
                        "linked_source_pack_ids": item.get("linked_source_pack_ids", []),
                    }
                ),
            }
        )
    return rows


def build_release_channels(
    profile: dict[str, Any],
    source_pack_index: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ready_pack_ids = {str(row.get("id")) for row in source_pack_index if row.get("status") == "ready"}
    required_pack_ids = {str(row.get("id")) for row in source_pack_index if row.get("required")}
    channels: list[dict[str, Any]] = []
    for channel in as_list(profile.get("release_channels"), "release_channels"):
        item = as_dict(channel, "release_channel")
        missing_required_packs = sorted(required_pack_ids - ready_pack_ids)
        requires_customer_runtime = bool(item.get("requires_customer_runtime_evidence"))
        status = "ready_for_release_evaluation" if not missing_required_packs else "hold_for_source_pack_readiness"
        channels.append(
            {
                **item,
                "channel_hash": stable_hash(
                    {
                        "allowed_payload_classes": item.get("allowed_payload_classes", []),
                        "id": item.get("id"),
                        "required_controls": item.get("required_controls", []),
                        "requires_customer_runtime_evidence": requires_customer_runtime,
                        "requires_signature": bool(item.get("requires_signature")),
                        "requires_tenant_binding": bool(item.get("requires_tenant_binding")),
                    }
                ),
                "missing_required_source_pack_ids": missing_required_packs,
                "status": status,
            }
        )
    return channels


def build_hosted_api_surface(profile: dict[str, Any]) -> dict[str, Any]:
    surface = as_dict(profile.get("hosted_api_surface"), "hosted_api_surface")
    endpoints = []
    for endpoint in as_list(surface.get("endpoints"), "hosted_api_surface.endpoints"):
        item = as_dict(endpoint, "hosted_api_surface endpoint")
        endpoints.append(
            {
                **item,
                "endpoint_hash": stable_hash(
                    {
                        "id": item.get("id"),
                        "linked_object_type_ids": item.get("linked_object_type_ids", []),
                        "linked_source_pack_ids": item.get("linked_source_pack_ids", []),
                        "method": item.get("method"),
                        "path": item.get("path"),
                    }
                ),
                "status": "contract_defined",
            }
        )
    premium = [endpoint for endpoint in endpoints if endpoint.get("premium_surface")]
    return {
        "base_path": surface.get("base_path"),
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
        "premium_endpoint_count": len(premium),
        "version": surface.get("version"),
    }


def build_buyer_views(profile: dict[str, Any], release_channels: list[dict[str, Any]]) -> list[dict[str, Any]]:
    channels_by_id = {str(channel.get("id")): channel for channel in release_channels}
    views: list[dict[str, Any]] = []
    for view in as_list(profile.get("buyer_views"), "buyer_views"):
        item = as_dict(view, "buyer_view")
        required_ids = [str(channel_id) for channel_id in item.get("required_release_channels", []) or []]
        required = [channels_by_id[channel_id] for channel_id in required_ids if channel_id in channels_by_id]
        views.append(
            {
                **item,
                "release_channel_status": {
                    channel_id: channels_by_id[channel_id].get("status")
                    for channel_id in required_ids
                    if channel_id in channels_by_id
                },
                "ready": all(channel.get("status") == "ready_for_release_evaluation" for channel in required),
            }
        )
    return views


def build_summary(
    *,
    source_pack_index: list[dict[str, Any]],
    evidence_object_types: list[dict[str, Any]],
    release_channels: list[dict[str, Any]],
    hosted_api_surface: dict[str, Any],
    failures: list[str],
) -> dict[str, Any]:
    pack_status = Counter(str(row.get("status")) for row in source_pack_index)
    channel_status = Counter(str(row.get("status")) for row in release_channels)
    ready_packs = pack_status.get("ready", 0)
    total_packs = len(source_pack_index)
    readiness_score = round((ready_packs / max(total_packs, 1)) * 100, 2)
    return {
        "api_endpoint_count": hosted_api_surface.get("endpoint_count"),
        "evidence_object_type_count": len(evidence_object_types),
        "failure_count": len(failures),
        "premium_api_endpoint_count": hosted_api_surface.get("premium_endpoint_count"),
        "readiness_score": readiness_score,
        "release_channel_count": len(release_channels),
        "release_channel_status": dict(channel_status),
        "source_pack_count": total_packs,
        "source_pack_status": dict(pack_status),
        "status": "ready_for_release_evaluation" if not failures and readiness_score == 100 else "needs_attention",
    }


def source_artifacts(
    *,
    profile_path: Path,
    profile_ref: Path,
    source_pack_index: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "secure_context_evidence_contract_profile": {
            "path": normalize_path(profile_ref),
            "sha256": sha256_file(profile_path),
        },
        "source_packs": {
            str(row.get("id")): {
                "path": row.get("path"),
                "sha256": row.get("sha256"),
                "status": row.get("status"),
            }
            for row in source_pack_index
        },
    }


def build_contract(profile: dict[str, Any], profile_path: Path, profile_ref: Path, repo_root: Path) -> dict[str, Any]:
    failures = validate_profile(profile, repo_root)
    packs, pack_failures = load_source_packs(profile, repo_root)
    failures.extend(pack_failures)
    source_pack_index = build_source_pack_index(profile, packs, repo_root)
    evidence_object_types = build_evidence_object_types(profile)
    release_channels = build_release_channels(profile, source_pack_index)
    hosted_api_surface = build_hosted_api_surface(profile)
    buyer_views = build_buyer_views(profile, release_channels)

    contract = {
        "buyer_views": buyer_views,
        "commercialization_path": {
            "open_reference": "Keep the public corpus useful, source-backed, and independently verifiable.",
            "team_layer": "Use private release channels for design partners that need tenant-bound runtime proof.",
            "enterprise_layer": "Turn evidence release evaluation, trust-center export, MCP decisions, and receipt lookup into hosted API surfaces.",
            "acquirer_value": "A buyer gets a defined evidence contract that can be embedded into an agent platform, MCP gateway, AI trust center, or security operations product."
        },
        "evidence_contract_summary": build_summary(
            source_pack_index=source_pack_index,
            evidence_object_types=evidence_object_types,
            release_channels=release_channels,
            hosted_api_surface=hosted_api_surface,
            failures=failures,
        ),
        "evidence_object_types": evidence_object_types,
        "failures": failures,
        "generated_at": str(profile.get("last_reviewed") or "2026-05-04"),
        "hosted_api_surface": hosted_api_surface,
        "positioning": profile.get("positioning", {}),
        "release_channels": release_channels,
        "release_contract": profile.get("release_contract", {}),
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": source_artifacts(
            profile_path=profile_path,
            profile_ref=profile_ref,
            source_pack_index=source_pack_index,
        ),
        "source_pack_index": source_pack_index,
        "source_references": profile.get("source_references", []),
    }
    return contract


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="Fail if the generated pack differs from the output file.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path.cwd()
    profile_ref = args.profile
    output_ref = args.output
    profile_path = resolve(repo_root, profile_ref)
    output_path = resolve(repo_root, output_ref)

    try:
        profile = load_json(profile_path)
        contract = build_contract(profile, profile_path, profile_ref, repo_root)
        rendered = stable_json(contract)
        if args.check:
            if not output_path.exists():
                print(f"{output_ref} does not exist", file=sys.stderr)
                return 1
            current = output_path.read_text(encoding="utf-8")
            if current != rendered:
                print(f"{output_ref} is stale; run scripts/generate_secure_context_evidence_contract.py", file=sys.stderr)
                return 1
            if contract.get("failures"):
                print("\n".join(str(failure) for failure in contract["failures"]), file=sys.stderr)
                return 1
            print(f"{output_ref} is current")
            return 0

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        if contract.get("failures"):
            print("\n".join(str(failure) for failure in contract["failures"]), file=sys.stderr)
            return 1
        print(f"Wrote {output_ref}")
        return 0
    except EvidenceContractError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
