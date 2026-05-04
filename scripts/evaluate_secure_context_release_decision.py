#!/usr/bin/env python3
"""Evaluate one secure-context release decision."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_RELEASE_PACK = Path("data/context/secure-context-release-pack.json")
VALID_DECISIONS = {
    "allow_context_release",
    "allow_open_reference_release",
    "deny_release_channel_mismatch",
    "deny_release_hash_mismatch",
    "deny_unregistered_release_source",
    "hold_for_eval_replay",
    "hold_for_poisoning_review",
    "hold_for_recertification",
    "hold_for_signature",
    "kill_session_on_release_violation",
}
PROHIBITED_DATA_CLASSES = {
    "private_key",
    "seed_phrase",
    "live_signing_material",
    "raw_access_token",
    "production_credential",
    "unredacted_pii_bulk",
    "unrestricted_customer_log",
}


class SecureContextReleaseDecisionError(RuntimeError):
    """Raised when release decision inputs are invalid."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SecureContextReleaseDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SecureContextReleaseDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SecureContextReleaseDecisionError(f"{path} root must be a JSON object")
    return payload


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def release_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(release.get("release_id")): release
        for release in as_list(pack.get("release_manifest"))
        if isinstance(release, dict) and release.get("release_id")
    }


def signed_environment(pack: dict[str, Any], environment: str) -> bool:
    contract = as_dict(pack.get("release_contract"))
    return environment in {str(item) for item in as_list(contract.get("signed_environments"))}


def open_environment(pack: dict[str, Any], environment: str) -> bool:
    contract = as_dict(pack.get("release_contract"))
    return environment in {str(item) for item in as_list(contract.get("open_reference_environments"))}


def release_preview(release: dict[str, Any] | None) -> dict[str, Any] | None:
    if release is None:
        return None
    return {
        "channel": release.get("channel"),
        "context_package_hash": release.get("context_package_hash"),
        "default_release_decision": release.get("default_release_decision"),
        "release_id": release.get("release_id"),
        "release_manifest_hash": release.get("release_manifest_hash"),
        "signature_policy": release.get("signature_policy"),
        "source_ids": release.get("source_ids", []),
        "title": release.get("title"),
        "workflow_id": release.get("workflow_id"),
    }


def decision_result(
    *,
    decision: str,
    reason: str,
    request: dict[str, Any],
    release: dict[str, Any] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise SecureContextReleaseDecisionError(f"unknown release decision {decision!r}")
    return {
        "allowed": decision in {"allow_context_release", "allow_open_reference_release"},
        "decision": decision,
        "evidence": {
            "blockers": release.get("blockers", []) if release else [],
            "release_manifest_hash": release.get("release_manifest_hash") if release else None,
            "source_artifacts": release.get("source_artifacts") if release else None,
            "source_hashes": release.get("source_hashes", {}) if release else {},
        },
        "matched_release": release_preview(release),
        "reason": reason,
        "request": {
            "channel_id": request.get("channel_id"),
            "contains_prohibited_data": request.get("contains_prohibited_data"),
            "data_classes": request.get("data_classes", []),
            "environment": request.get("environment"),
            "release_id": request.get("release_id"),
            "requested_source_ids": request.get("requested_source_ids", []),
            "signature_bundle_present": request.get("signature_bundle_present"),
            "transparency_log_verified": request.get("transparency_log_verified"),
        },
        "violations": violations or [],
    }


def evaluate_secure_context_release_decision(
    release_pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured decision for one secure-context release request."""
    if not isinstance(release_pack, dict):
        raise SecureContextReleaseDecisionError("release_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise SecureContextReleaseDecisionError("runtime_request must be an object")

    request = dict(runtime_request)
    request["release_id"] = str(request.get("release_id") or "").strip()
    request["channel_id"] = str(request.get("channel_id") or "").strip()
    request["environment"] = str(request.get("environment") or "open_reference").strip()
    request["requested_source_ids"] = [str(item) for item in as_list(request.get("requested_source_ids")) if str(item)]
    request["source_hashes"] = as_dict(request.get("source_hashes"))
    request["data_classes"] = [str(item) for item in as_list(request.get("data_classes")) if str(item)]
    request["signature_bundle_present"] = as_bool(request.get("signature_bundle_present"))
    request["transparency_log_verified"] = as_bool(request.get("transparency_log_verified"))
    request["contains_prohibited_data"] = as_bool(request.get("contains_prohibited_data"))
    request["runtime_kill_signal"] = str(request.get("runtime_kill_signal") or "").strip()

    if request["contains_prohibited_data"] or request["runtime_kill_signal"]:
        return decision_result(
            decision="kill_session_on_release_violation",
            reason="release request contains a runtime kill signal or prohibited context",
            request=request,
            violations=[request["runtime_kill_signal"] or "contains_prohibited_data"],
        )

    forbidden = sorted(set(request["data_classes"]).intersection(PROHIBITED_DATA_CLASSES))
    if forbidden:
        return decision_result(
            decision="kill_session_on_release_violation",
            reason="release request includes prohibited data classes",
            request=request,
            violations=[f"prohibited data class: {item}" for item in forbidden],
        )

    if not (open_environment(release_pack, request["environment"]) or signed_environment(release_pack, request["environment"])):
        return decision_result(
            decision="deny_release_channel_mismatch",
            reason="environment is not registered in the release contract",
            request=request,
            violations=[f"unknown environment: {request['environment']}"],
        )

    release = release_by_id(release_pack).get(request["release_id"])
    if release is None:
        return decision_result(
            decision="deny_unregistered_release_source",
            reason="release_id is not registered in the release pack",
            request=request,
            violations=[f"unknown release_id: {request['release_id']}"],
        )

    channel = as_dict(release.get("channel"))
    if request["channel_id"] and request["channel_id"] != channel.get("id"):
        return decision_result(
            decision="deny_release_channel_mismatch",
            reason="requested channel does not match the release manifest channel",
            request=request,
            release=release,
            violations=[f"expected channel {channel.get('id')}, got {request['channel_id']}"],
        )

    release_sources = {str(item) for item in as_list(release.get("source_ids"))}
    requested_sources = set(request["requested_source_ids"])
    unknown_sources = sorted(requested_sources - release_sources)
    if unknown_sources:
        return decision_result(
            decision="deny_unregistered_release_source",
            reason="request asks for sources outside the release manifest",
            request=request,
            release=release,
            violations=[f"source not in release: {source_id}" for source_id in unknown_sources],
        )

    expected_hashes = as_dict(release.get("source_hashes"))
    mismatches = [
        source_id
        for source_id, supplied_hash in request["source_hashes"].items()
        if str(expected_hashes.get(source_id) or "") != str(supplied_hash)
    ]
    if mismatches:
        return decision_result(
            decision="deny_release_hash_mismatch",
            reason="runtime-supplied source hashes do not match the generated release manifest",
            request=request,
            release=release,
            violations=[f"source hash mismatch: {source_id}" for source_id in sorted(mismatches)],
        )

    base_decision = str(release.get("default_release_decision") or "")
    if base_decision in {
        "deny_unregistered_release_source",
        "hold_for_eval_replay",
        "hold_for_poisoning_review",
        "hold_for_recertification",
        "kill_session_on_release_violation",
    }:
        return decision_result(
            decision=base_decision,
            reason="generated release manifest is not currently promotable",
            request=request,
            release=release,
            violations=release.get("blockers", []),
        )

    signature_required = bool(channel.get("requires_signature")) or signed_environment(release_pack, request["environment"])
    if signature_required and not (request["signature_bundle_present"] and request["transparency_log_verified"]):
        return decision_result(
            decision="hold_for_signature",
            reason="release channel requires signature bundle and transparency-log proof",
            request=request,
            release=release,
            violations=["signature_bundle_present", "transparency_log_verified"],
        )

    if base_decision == "allow_open_reference_release" and not signature_required:
        return decision_result(
            decision="allow_open_reference_release",
            reason="open-reference release is active and hash-matched",
            request=request,
            release=release,
        )

    return decision_result(
        decision="allow_context_release",
        reason="release is active, hash-matched, and satisfies channel signature requirements",
        request=request,
        release=release,
    )


def source_hash_args(values: list[str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise SecureContextReleaseDecisionError("--source-hash values must use source_id=sha256")
        key, raw = value.split("=", 1)
        output[key.strip()] = raw.strip()
    return output


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.request:
        payload = load_json(args.request)
    else:
        payload = {}
    payload.update(
        {
            "channel_id": args.channel_id,
            "contains_prohibited_data": args.contains_prohibited_data,
            "data_classes": args.data_class or [],
            "environment": args.environment,
            "release_id": args.release_id,
            "requested_source_ids": args.source_id or [],
            "runtime_kill_signal": args.runtime_kill_signal,
            "signature_bundle_present": args.signature_bundle_present,
            "source_hashes": source_hash_args(args.source_hash or []),
            "transparency_log_verified": args.transparency_log_verified,
        }
    )
    return payload


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-pack", type=Path, default=DEFAULT_RELEASE_PACK)
    parser.add_argument("--request", type=Path, help="JSON file containing runtime request attributes")
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--channel-id", default="")
    parser.add_argument("--environment", default="open_reference")
    parser.add_argument("--source-id", action="append")
    parser.add_argument("--source-hash", action="append")
    parser.add_argument("--data-class", action="append")
    parser.add_argument("--runtime-kill-signal", default="")
    parser.add_argument("--contains-prohibited-data", action="store_true")
    parser.add_argument("--signature-bundle-present", action="store_true")
    parser.add_argument("--transparency-log-verified", action="store_true")
    parser.add_argument("--expect-decision", choices=sorted(VALID_DECISIONS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        pack = load_json(args.release_pack)
        request = request_from_args(args)
        decision = evaluate_secure_context_release_decision(pack, request)
    except SecureContextReleaseDecisionError as exc:
        print(f"secure context release decision failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(decision, indent=2, sort_keys=True))
    if args.expect_decision and decision.get("decision") != args.expect_decision:
        print(
            f"expected decision {args.expect_decision!r}, got {decision.get('decision')!r}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
