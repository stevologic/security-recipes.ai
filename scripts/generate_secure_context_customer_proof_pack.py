#!/usr/bin/env python3
"""Generate the SecurityRecipes secure context customer proof pack.

The pack turns the existing buyer, pilot, telemetry, receipt, MCP, and
value-model artifacts into a customer-proof contract. It is intentionally
honest: the public repo can prove the reference control package, while
customer runtime events are still required before renewal or acquisition
claims are credible.
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
DEFAULT_PROFILE = Path("data/assurance/secure-context-customer-proof-profile.json")
DEFAULT_OUTPUT = Path("data/evidence/secure-context-customer-proof-pack.json")
DEFAULT_SOURCE_PACKS: dict[str, Path] = {
    "agentic_app_intake_pack": Path("data/evidence/agentic-app-intake-pack.json"),
    "agentic_protocol_conformance_pack": Path("data/evidence/agentic-protocol-conformance-pack.json"),
    "agentic_run_receipt_pack": Path("data/evidence/agentic-run-receipt-pack.json"),
    "agentic_source_freshness_watch": Path("data/evidence/agentic-source-freshness-watch.json"),
    "agentic_telemetry_contract": Path("data/evidence/agentic-telemetry-contract.json"),
    "design_partner_pilot_pack": Path("data/evidence/design-partner-pilot-pack.json"),
    "enterprise_trust_center_export": Path("data/evidence/enterprise-trust-center-export.json"),
    "mcp_authorization_conformance_pack": Path("data/evidence/mcp-authorization-conformance-pack.json"),
    "secure_context_eval_pack": Path("data/evidence/secure-context-eval-pack.json"),
    "secure_context_value_model": Path("data/evidence/secure-context-value-model.json"),
}


class CustomerProofPackError(RuntimeError):
    """Raised when the customer proof pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CustomerProofPackError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise CustomerProofPackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CustomerProofPackError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CustomerProofPackError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CustomerProofPackError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def evidence_source_rows(profile: dict[str, Any]) -> list[dict[str, Any]]:
    rows = as_list(profile.get("evidence_sources"), "evidence_sources")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx, row in enumerate(rows):
        item = as_dict(row, f"evidence_sources[{idx}]")
        key = str(item.get("key", "")).strip()
        if key in seen:
            raise CustomerProofPackError(f"evidence_sources duplicate key: {key}")
        seen.add(key)
        output.append(item)
    return output


def validate_profile(profile: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(profile.get("schema_version") == PACK_SCHEMA_VERSION, failures, "profile schema_version must be 1.0")
    require(len(str(profile.get("intent", ""))) >= 120, failures, "profile intent must explain the proof goal")

    sources = as_list(profile.get("source_references"), "source_references")
    require(len(sources) >= 6, failures, "source_references must include current OWASP, MCP, NIST, CISA, and telemetry sources")
    source_ids: set[str] = set()
    source_classes: set[str] = set()
    for idx, source in enumerate(sources):
        item = as_dict(source, f"source_references[{idx}]")
        source_id = str(item.get("id", "")).strip()
        require(bool(source_id), failures, f"source_references[{idx}].id is required")
        require(source_id not in source_ids, failures, f"{source_id}: duplicate source id")
        source_ids.add(source_id)
        source_classes.add(str(item.get("source_class", "")).strip())
        require(str(item.get("url", "")).startswith("https://"), failures, f"{source_id}: url must be https")
        require(str(item.get("publisher", "")).strip(), failures, f"{source_id}: publisher is required")
        require(len(str(item.get("why_it_matters", ""))) >= 70, failures, f"{source_id}: why_it_matters must be specific")
    for required_class in {
        "government_framework",
        "government_guidance",
        "industry_standard",
        "protocol_specification",
        "telemetry_standard",
    }:
        require(required_class in source_classes, failures, f"source_references must include {required_class}")

    contract = as_dict(profile.get("proof_contract"), "proof_contract")
    require(
        contract.get("default_state") == "not_acquisition_ready_until_customer_runtime_evidence_is_bound",
        failures,
        "proof_contract.default_state must block acquisition claims until customer proof exists",
    )
    required_pack_keys = {str(item) for item in as_list(contract.get("required_source_pack_keys"), "required_source_pack_keys")}
    unknown_pack_keys = sorted(required_pack_keys - set(DEFAULT_SOURCE_PACKS))
    require(not unknown_pack_keys, failures, f"unknown required source pack keys: {unknown_pack_keys}")
    require(
        len(required_pack_keys) >= int(contract.get("minimum_source_packs") or 0),
        failures,
        "required_source_pack_keys below minimum_source_packs",
    )
    for key in required_pack_keys:
        require(resolve(repo_root, DEFAULT_SOURCE_PACKS[key]).exists(), failures, f"{key}: source pack path does not exist: {DEFAULT_SOURCE_PACKS[key]}")
    require(len(as_list(contract.get("required_mcp_tools"), "required_mcp_tools")) >= len(required_pack_keys), failures, "required_mcp_tools must cover source packs and customer proof tool")
    require(len(as_list(contract.get("proof_success_criteria"), "proof_success_criteria")) >= 5, failures, "proof_success_criteria are incomplete")

    evidence_sources = evidence_source_rows(profile)
    evidence_keys = {str(row.get("key")) for row in evidence_sources}
    require(not sorted(required_pack_keys - evidence_keys), failures, f"evidence_sources missing required packs: {sorted(required_pack_keys - evidence_keys)}")
    for row in evidence_sources:
        key = str(row.get("key", "")).strip()
        path = Path(str(row.get("path", "")))
        require(key in DEFAULT_SOURCE_PACKS, failures, f"{key}: unknown evidence source key")
        require(path == DEFAULT_SOURCE_PACKS.get(key), failures, f"{key}: evidence source path must match generator default")
        require(resolve(repo_root, path).exists(), failures, f"{key}: path does not exist: {path}")
        require(len(str(row.get("proof_role", ""))) >= 60, failures, f"{key}: proof_role must be specific")

    claims = as_list(profile.get("proof_claims"), "proof_claims")
    require(len(claims) >= int(contract.get("minimum_proof_claims") or 0), failures, "proof_claims below minimum")
    claim_ids: set[str] = set()
    for idx, claim in enumerate(claims):
        item = as_dict(claim, f"proof_claims[{idx}]")
        claim_id = str(item.get("id", "")).strip()
        claim_ids.add(claim_id)
        require(bool(claim_id), failures, f"proof_claims[{idx}].id is required")
        packs = {str(key) for key in as_list(item.get("evidence_pack_keys"), f"{claim_id}.evidence_pack_keys")}
        require(not sorted(packs - required_pack_keys), failures, f"{claim_id}: unknown evidence pack keys {sorted(packs - required_pack_keys)}")
        require(len(as_list(item.get("required_runtime_fields"), f"{claim_id}.required_runtime_fields")) >= 5, failures, f"{claim_id}: runtime fields are incomplete")
        require(int(item.get("minimum_signal_count") or 0) >= 1, failures, f"{claim_id}: minimum_signal_count must be >= 1")
        require(len(str(item.get("blocked_until", ""))) >= 60, failures, f"{claim_id}: blocked_until must be specific")

    events = as_list(profile.get("runtime_event_classes"), "runtime_event_classes")
    require(len(events) >= int(contract.get("minimum_runtime_event_classes") or 0), failures, "runtime_event_classes below minimum")
    event_ids: set[str] = set()
    for idx, event in enumerate(events):
        item = as_dict(event, f"runtime_event_classes[{idx}]")
        event_id = str(item.get("id", "")).strip()
        require(bool(event_id), failures, f"runtime_event_classes[{idx}].id is required")
        require(event_id not in event_ids, failures, f"{event_id}: duplicate event id")
        event_ids.add(event_id)
        require(len(as_list(item.get("required_fields"), f"{event_id}.required_fields")) >= 5, failures, f"{event_id}: required_fields are incomplete")

    metrics = as_list(profile.get("metric_definitions"), "metric_definitions")
    require(len(metrics) >= int(contract.get("minimum_metric_definitions") or 0), failures, "metric_definitions below minimum")
    metric_ids: set[str] = set()
    for idx, metric in enumerate(metrics):
        item = as_dict(metric, f"metric_definitions[{idx}]")
        metric_id = str(item.get("id", "")).strip()
        require(bool(metric_id), failures, f"metric_definitions[{idx}].id is required")
        require(metric_id not in metric_ids, failures, f"{metric_id}: duplicate metric id")
        metric_ids.add(metric_id)
        mapped_claims = {str(claim_id) for claim_id in as_list(item.get("proof_claim_ids"), f"{metric_id}.proof_claim_ids")}
        require(not sorted(mapped_claims - claim_ids), failures, f"{metric_id}: unknown proof_claim_ids {sorted(mapped_claims - claim_ids)}")
        require(len(as_list(item.get("telemetry_fields"), f"{metric_id}.telemetry_fields")) >= 3, failures, f"{metric_id}: telemetry_fields are incomplete")
        require(str(item.get("target", "")).strip(), failures, f"{metric_id}: target is required")

    gates = as_list(profile.get("renewal_gates"), "renewal_gates")
    require(len(gates) >= int(contract.get("minimum_renewal_gates") or 0), failures, "renewal_gates below minimum")
    for idx, gate in enumerate(gates):
        item = as_dict(gate, f"renewal_gates[{idx}]")
        gate_id = str(item.get("id", "")).strip()
        linked = {str(metric_id) for metric_id in as_list(item.get("linked_metric_ids"), f"{gate_id}.linked_metric_ids")}
        require(bool(gate_id), failures, f"renewal_gates[{idx}].id is required")
        require(not sorted(linked - metric_ids), failures, f"{gate_id}: unknown linked_metric_ids {sorted(linked - metric_ids)}")
        require(len(str(item.get("what_passes", ""))) >= 50, failures, f"{gate_id}: what_passes must be specific")

    risks = as_list(profile.get("risk_register"), "risk_register")
    require(len(risks) >= 5, failures, "risk_register must include customer proof risks")
    for idx, risk in enumerate(risks):
        item = as_dict(risk, f"risk_register[{idx}]")
        require(str(item.get("id", "")).strip(), failures, f"risk_register[{idx}].id is required")
        require(len(str(item.get("mitigation", ""))) >= 60, failures, f"{item.get('id')}: mitigation must be specific")
    return failures


def load_source_packs(profile: dict[str, Any], repo_root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    packs: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    required_keys = {str(item) for item in profile.get("proof_contract", {}).get("required_source_pack_keys", [])}
    for key in sorted(required_keys):
        ref = DEFAULT_SOURCE_PACKS.get(key)
        if ref is None:
            failures.append(f"{key}: no default source pack path")
            continue
        try:
            packs[key] = load_json(resolve(repo_root, ref))
        except CustomerProofPackError as exc:
            failures.append(f"{key}: {exc}")
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
    for key, value in pack.items():
        if key.endswith("_summary") and isinstance(value, dict) and isinstance(value.get("failure_count"), int):
            return int(value["failure_count"])
    return 0


def pack_summary(pack: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(pack, dict):
        return None
    for key, value in pack.items():
        if key.endswith("_summary") and isinstance(value, dict):
            return {"key": key, "value": value}
    for key in ["export_summary", "value_model_summary", "pilot_summary", "telemetry_summary"]:
        value = pack.get(key)
        if isinstance(value, dict):
            return {"key": key, "value": value}
    return None


def source_pack_index(profile: dict[str, Any], packs: dict[str, dict[str, Any]], repo_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    sources_by_key = {str(row.get("key")): row for row in evidence_source_rows(profile)}
    required_keys = {str(item) for item in profile.get("proof_contract", {}).get("required_source_pack_keys", [])}
    for key in sorted(required_keys):
        ref = DEFAULT_SOURCE_PACKS[key]
        path = resolve(repo_root, ref)
        pack = packs.get(key)
        failure_count = pack_failure_count(pack)
        source = sources_by_key.get(key, {})
        rows.append(
            {
                "available": path.exists() and isinstance(pack, dict),
                "failure_count": failure_count,
                "key": key,
                "path": normalize_path(ref),
                "proof_role": source.get("proof_role"),
                "schema_version": pack.get("schema_version") if isinstance(pack, dict) else None,
                "sha256": sha256_file(path) if path.exists() else None,
                "status": "ready" if path.exists() and failure_count == 0 else "needs_attention",
                "summary": pack_summary(pack),
                "title": source.get("title"),
            }
        )
    return rows


def evidence_status(pack_keys: list[str], packs_by_key: dict[str, dict[str, Any]]) -> dict[str, Any]:
    evidence = [packs_by_key[key] for key in pack_keys if key in packs_by_key]
    missing = [key for key in pack_keys if key not in packs_by_key]
    ready_count = sum(1 for row in evidence if row.get("status") == "ready")
    return {
        "evidence_paths": [row.get("path") for row in evidence],
        "missing_pack_keys": missing,
        "ready_evidence_count": ready_count,
        "status": "reference_evidence_ready" if not missing and ready_count == len(pack_keys) else "needs_source_pack_attention",
        "total_evidence_count": len(pack_keys),
    }


def build_proof_claims(profile: dict[str, Any], pack_index: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packs_by_key = {str(row.get("key")): row for row in pack_index}
    rows: list[dict[str, Any]] = []
    for claim in profile.get("proof_claims", []) or []:
        if not isinstance(claim, dict):
            continue
        pack_keys = [str(key) for key in claim.get("evidence_pack_keys", []) or []]
        evidence = evidence_status(pack_keys, packs_by_key)
        rows.append(
            {
                **claim,
                "customer_proof_state": "customer_runtime_evidence_required",
                "evidence_status": evidence,
                "status": "reference_ready_customer_runtime_required"
                if evidence.get("status") == "reference_evidence_ready"
                else "needs_reference_evidence_attention",
            }
        )
    return rows


def build_metrics(profile: dict[str, Any], claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    claims_by_id = {str(claim.get("id")): claim for claim in claims}
    rows: list[dict[str, Any]] = []
    for metric in profile.get("metric_definitions", []) or []:
        if not isinstance(metric, dict):
            continue
        claim_ids = [str(item) for item in metric.get("proof_claim_ids", []) or []]
        claim_states = [
            {
                "id": claim_id,
                "status": claims_by_id.get(claim_id, {}).get("status", "missing_claim"),
            }
            for claim_id in claim_ids
        ]
        rows.append(
            {
                **metric,
                "claim_states": claim_states,
                "status": "customer_metric_required",
            }
        )
    return rows


def build_renewal_gates(profile: dict[str, Any], metrics: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metrics_by_id = {str(metric.get("id")): metric for metric in metrics}
    rows: list[dict[str, Any]] = []
    for gate in profile.get("renewal_gates", []) or []:
        if not isinstance(gate, dict):
            continue
        metric_ids = [str(item) for item in gate.get("linked_metric_ids", []) or []]
        rows.append(
            {
                **gate,
                "metric_statuses": [
                    {
                        "id": metric_id,
                        "status": metrics_by_id.get(metric_id, {}).get("status", "missing_metric"),
                        "target": metrics_by_id.get(metric_id, {}).get("target"),
                    }
                    for metric_id in metric_ids
                ],
                "status": "blocked_until_customer_evidence_passes_gate",
            }
        )
    return rows


def source_artifacts(profile_path: Path, profile_ref: Path, pack_index: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "secure_context_customer_proof_profile": {
            "path": normalize_path(profile_ref),
            "sha256": sha256_file(profile_path),
        },
        "source_packs": [
            {
                "key": row.get("key"),
                "path": row.get("path"),
                "sha256": row.get("sha256"),
            }
            for row in pack_index
        ],
    }


def customer_proof_summary(
    *,
    failures: list[str],
    pack_index: list[dict[str, Any]],
    claims: list[dict[str, Any]],
    metrics: list[dict[str, Any]],
    gates: list[dict[str, Any]],
) -> dict[str, Any]:
    pack_status = Counter(str(row.get("status")) for row in pack_index)
    claim_status = Counter(str(row.get("status")) for row in claims)
    return {
        "claim_count": len(claims),
        "default_state": "reference_evidence_ready_customer_runtime_proof_required",
        "failure_count": len(failures),
        "metric_count": len(metrics),
        "pack_count": len(pack_index),
        "pack_status_counts": dict(sorted(pack_status.items())),
        "proof_claim_status_counts": dict(sorted(claim_status.items())),
        "ready_source_pack_count": pack_status.get("ready", 0),
        "renewal_gate_count": len(gates),
        "status": "customer_proof_contract_ready"
        if not failures and pack_status.get("needs_attention", 0) == 0
        else "needs_attention_before_customer_proof",
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
    pack_index = source_pack_index(profile, packs, repo_root)
    claims = build_proof_claims(profile, pack_index)
    metrics = build_metrics(profile, claims)
    gates = build_renewal_gates(profile, metrics)
    return {
        "acquirer_readout": profile.get("acquirer_readout", {}),
        "customer_proof_pack_id": "security-recipes-secure-context-customer-proof-pack",
        "customer_proof_summary": customer_proof_summary(
            failures=failures,
            pack_index=pack_index,
            claims=claims,
            metrics=metrics,
            gates=gates,
        ),
        "evidence_sources": profile.get("evidence_sources", []),
        "failures": failures,
        "generated_at": generated_at or str(profile.get("last_reviewed", "")),
        "intent": profile.get("intent"),
        "metric_definitions": metrics,
        "positioning": profile.get("positioning", {}),
        "proof_claims": claims,
        "proof_contract": profile.get("proof_contract", {}),
        "renewal_gates": gates,
        "risk_register": profile.get("risk_register", []),
        "runtime_event_classes": profile.get("runtime_event_classes", []),
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": source_artifacts(profile_path, profile_ref, pack_index),
        "source_pack_index": pack_index,
        "source_references": profile.get("source_references", []),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in customer proof pack is stale.")
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
        for row in pack.get("source_pack_index", []):
            if isinstance(row, dict) and row.get("status") != "ready":
                failures.append(f"{row.get('key')}: required source pack is not ready")
    except CustomerProofPackError as exc:
        print(f"secure context customer proof pack generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("secure context customer proof pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_secure_context_customer_proof_pack.py", file=sys.stderr)
            return 1
        if current_text != rendered:
            print(f"{output_path} is stale; run scripts/generate_secure_context_customer_proof_pack.py", file=sys.stderr)
            return 1
        print(f"Validated secure context customer proof pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    if failures:
        print("Generated secure context customer proof pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated secure context customer proof pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
