#!/usr/bin/env python3
"""Evaluate one agent skill supply-chain decision.

The generated pack declares which agentic skills, rules files, hooks, and
behavior packages are trusted enough to install, update, or run. This
evaluator is the deterministic policy function an MCP gateway, agent host,
CI admission check, or audit replay can call before a skill inherits
filesystem, network, memory, shell, or MCP authority.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_SKILL_PACK = Path("data/evidence/agent-skill-supply-chain-pack.json")
VALID_DECISIONS = {
    "allow_pinned_readonly_skill",
    "allow_guarded_skill",
    "hold_for_skill_security_review",
    "deny_untrusted_skill",
    "deny_unregistered_skill",
    "kill_session_on_malicious_skill_signal",
}
ALLOW_DECISIONS = {"allow_pinned_readonly_skill", "allow_guarded_skill"}
WRITE_OPERATIONS = {"install", "update", "enable", "run", "export"}
PRIVATE_DATA_CLASSES = {
    "private_key",
    "seed_phrase",
    "raw_access_token",
    "wallet_material",
    "browser_password",
    "production_credential",
}


class SkillDecisionError(RuntimeError):
    """Raised when the skill pack or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SkillDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SkillDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SkillDecisionError(f"{path} root must be a JSON object")
    return payload


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def approval_present(value: Any) -> bool:
    return isinstance(value, dict) and bool(value.get("id") or value.get("approval_id") or value.get("approved_at"))


def skills_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = pack.get("skill_profiles")
    if not isinstance(rows, list):
        raise SkillDecisionError("skill pack is missing skill_profiles")
    return {
        str(row.get("skill_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("skill_id")
    }


def skill_preview(skill: dict[str, Any] | None) -> dict[str, Any] | None:
    if skill is None:
        return None
    return {
        "allowed_workflow_ids": skill.get("allowed_workflow_ids", []),
        "decision": skill.get("decision"),
        "lethal_trifecta": skill.get("lethal_trifecta"),
        "package_hash": skill.get("package_hash"),
        "platforms": skill.get("platforms", []),
        "publisher": skill.get("publisher", {}),
        "registry": skill.get("registry", {}),
        "residual_risk_score": skill.get("residual_risk_score"),
        "risk_tier": skill.get("risk_tier"),
        "sandbox_required": skill.get("sandbox_required"),
        "scan_status": skill.get("scan_status"),
        "signature_present": skill.get("signature_present"),
        "skill_id": skill.get("skill_id"),
        "title": skill.get("title"),
        "version": skill.get("version"),
        "version_pinned": skill.get("version_pinned"),
    }


def has_private_data(requested_permissions: dict[str, Any]) -> bool:
    data_classes = {str(item) for item in as_list(requested_permissions.get("data_access_classes"))}
    paths = " ".join(str(item).lower() for item in as_list(requested_permissions.get("filesystem_read")))
    return bool(data_classes.intersection(PRIVATE_DATA_CLASSES)) or any(
        marker in paths for marker in [".env", ".pem", ".key", "wallet", "browser", "password", "token", "secret"]
    )


def has_network(request: dict[str, Any], requested_permissions: dict[str, Any]) -> bool:
    return bool(request.get("network_egress_domains") or requested_permissions.get("network_egress"))


def has_untrusted_execution(requested_permissions: dict[str, Any]) -> bool:
    return bool(
        requested_permissions.get("shell")
        or requested_permissions.get("identity_file_write")
        or requested_permissions.get("persistent_memory")
    )


def decision_result(
    *,
    decision: str,
    reason: str,
    request: dict[str, Any],
    pack: dict[str, Any],
    skill: dict[str, Any] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise SkillDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "evidence": {
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {})),
            "required_controls": skill.get("required_controls", []) if skill else [],
            "skill_pack_generated_at": pack.get("generated_at"),
            "source_artifacts": pack.get("source_artifacts"),
        },
        "matched_skill": skill_preview(skill),
        "reason": reason,
        "request": {
            "agent_id": request.get("agent_id"),
            "operation": request.get("operation"),
            "package_hash": request.get("package_hash"),
            "platform": request.get("platform"),
            "registry_verified": request.get("registry_verified"),
            "run_id": request.get("run_id"),
            "sandboxed": request.get("sandboxed"),
            "signature_present": request.get("signature_present"),
            "skill_id": request.get("skill_id"),
            "verified_publisher": request.get("verified_publisher"),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def evaluate_agent_skill_supply_chain_decision(
    skill_pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured runtime decision for one skill operation."""
    if not isinstance(skill_pack, dict):
        raise SkillDecisionError("skill_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise SkillDecisionError("runtime_request must be an object")

    request = dict(runtime_request)
    request["skill_id"] = str(request.get("skill_id") or "").strip()
    request["operation"] = str(request.get("operation") or "").strip().lower()
    request["workflow_id"] = str(request.get("workflow_id") or "").strip()
    request["platform"] = str(request.get("platform") or "").strip()
    request["package_hash"] = str(request.get("package_hash") or "").strip()
    request["runtime_kill_signal"] = str(request.get("runtime_kill_signal") or "").strip()
    request["signature_present"] = as_bool(request.get("signature_present"))
    request["verified_publisher"] = as_bool(request.get("verified_publisher"))
    request["registry_verified"] = as_bool(request.get("registry_verified"))
    request["sandboxed"] = as_bool(request.get("sandboxed"))
    request["network_egress_domains"] = [str(item) for item in as_list(request.get("network_egress_domains")) if item]
    requested_permissions = request.get("requested_permissions") if isinstance(request.get("requested_permissions"), dict) else {}

    if request["runtime_kill_signal"]:
        return decision_result(
            decision="kill_session_on_malicious_skill_signal",
            reason="runtime kill signal is present",
            request=request,
            pack=skill_pack,
            violations=[f"runtime_kill_signal: {request['runtime_kill_signal']}"],
        )

    if has_private_data(requested_permissions) and has_network(request, requested_permissions) and has_untrusted_execution(requested_permissions):
        return decision_result(
            decision="kill_session_on_malicious_skill_signal",
            reason="requested permissions combine private data access, external egress, and executable or persistent authority",
            request=request,
            pack=skill_pack,
            violations=["private_data_plus_egress_plus_execution"],
        )

    skills = skills_by_id(skill_pack)
    skill = skills.get(request["skill_id"]) if request["skill_id"] else None
    if skill is None:
        return decision_result(
            decision="deny_unregistered_skill",
            reason="skill is not registered in the supply-chain pack",
            request=request,
            pack=skill_pack,
            violations=["skill_id is missing or unregistered"],
        )

    violations: list[str] = []
    if not request["operation"]:
        violations.append("operation is required")
    elif request["operation"] not in WRITE_OPERATIONS:
        violations.append(f"operation is not recognized: {request['operation']}")
    if request["workflow_id"] and request["workflow_id"] not in {str(item) for item in skill.get("allowed_workflow_ids", []) or []}:
        violations.append(f"workflow_id is not approved for skill: {request['workflow_id']}")
    if request["platform"] and request["platform"] not in {str(item) for item in skill.get("platforms", []) or []}:
        violations.append(f"platform is not declared for skill: {request['platform']}")
    if skill.get("package_hash") and request["package_hash"] and request["package_hash"] != skill.get("package_hash"):
        violations.append("package_hash does not match registered skill hash")
    if skill.get("package_hash") and not request["package_hash"] and request["operation"] in {"install", "update", "enable"}:
        violations.append("package_hash is required for install, update, or enable")
    if skill.get("signature_present") and not request["signature_present"] and request["operation"] in {"install", "update", "enable"}:
        violations.append("signature_present is required for install, update, or enable")
    if skill.get("publisher", {}).get("verified") and not request["verified_publisher"] and request["operation"] in {"install", "update", "enable"}:
        violations.append("verified_publisher is required for install, update, or enable")
    if skill.get("registry", {}).get("verified") and not request["registry_verified"] and request["operation"] in {"install", "update", "enable"}:
        violations.append("registry_verified is required for install, update, or enable")
    if skill.get("sandbox_required") and not request["sandboxed"]:
        violations.append("sandboxed execution is required")
    if skill.get("human_approval_required") and request["operation"] in {"install", "update", "enable", "run"} and not approval_present(request.get("human_approval_record")):
        violations.append("human_approval_record is required")

    if skill.get("lethal_trifecta"):
        return decision_result(
            decision="kill_session_on_malicious_skill_signal",
            reason="registered skill matches prohibited private-data, egress, and executable authority pattern",
            request=request,
            pack=skill_pack,
            skill=skill,
            violations=violations or ["lethal_trifecta"],
        )

    registered_decision = str(skill.get("decision") or "")
    if registered_decision in {"deny_untrusted_skill", "kill_session_on_malicious_skill_signal"}:
        return decision_result(
            decision=registered_decision,
            reason="registered skill is not approved for runtime use",
            request=request,
            pack=skill_pack,
            skill=skill,
            violations=violations,
        )

    if violations:
        return decision_result(
            decision="hold_for_skill_security_review",
            reason="runtime request does not satisfy registered skill controls",
            request=request,
            pack=skill_pack,
            skill=skill,
            violations=violations,
        )

    if registered_decision not in VALID_DECISIONS:
        return decision_result(
            decision="hold_for_skill_security_review",
            reason="registered skill has an unknown decision",
            request=request,
            pack=skill_pack,
            skill=skill,
            violations=[f"unknown decision: {registered_decision}"],
        )

    return decision_result(
        decision=registered_decision,
        reason="runtime request satisfies agent skill supply-chain policy",
        request=request,
        pack=skill_pack,
        skill=skill,
    )


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.request:
        payload = load_json(args.request)
    else:
        payload = {}
    permissions = payload.get("requested_permissions") if isinstance(payload.get("requested_permissions"), dict) else {}
    if args.permission:
        for item in args.permission:
            key, _, value = item.partition("=")
            if not key or not value:
                continue
            if value.lower() in {"true", "false"}:
                permissions[key] = value.lower() == "true"
            else:
                permissions.setdefault(key, []).extend([part.strip() for part in value.split(",") if part.strip()])
    overrides = {
        "agent_id": args.agent_id,
        "human_approval_record": {"id": args.human_approval_id} if args.human_approval_id else None,
        "network_egress_domains": args.network_egress_domains,
        "operation": args.operation,
        "package_hash": args.package_hash,
        "platform": args.platform,
        "registry_verified": args.registry_verified,
        "requested_permissions": permissions,
        "run_id": args.run_id,
        "runtime_kill_signal": args.runtime_kill_signal,
        "sandboxed": args.sandboxed,
        "signature_present": args.signature_present,
        "skill_id": args.skill_id,
        "verified_publisher": args.verified_publisher,
        "workflow_id": args.workflow_id,
    }
    for key, value in overrides.items():
        if value not in (None, "", [], {}):
            payload[key] = value
    return payload


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill-pack", type=Path, default=DEFAULT_SKILL_PACK)
    parser.add_argument("--request", type=Path, help="JSON file containing runtime request attributes")
    parser.add_argument("--skill-id")
    parser.add_argument("--operation")
    parser.add_argument("--workflow-id")
    parser.add_argument("--platform")
    parser.add_argument("--agent-id")
    parser.add_argument("--run-id")
    parser.add_argument("--package-hash")
    parser.add_argument("--signature-present", action="store_true")
    parser.add_argument("--verified-publisher", action="store_true")
    parser.add_argument("--registry-verified", action="store_true")
    parser.add_argument("--sandboxed", action="store_true")
    parser.add_argument("--network-egress-domains", nargs="*", default=None)
    parser.add_argument("--permission", action="append", help="Requested permission override as key=value1,value2 or key=true")
    parser.add_argument("--human-approval-id")
    parser.add_argument("--runtime-kill-signal")
    parser.add_argument("--expect-decision", choices=sorted(VALID_DECISIONS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    skill_pack = load_json(args.skill_pack)
    request = request_from_args(args)
    decision = evaluate_agent_skill_supply_chain_decision(skill_pack, request)
    print(json.dumps(decision, indent=2, sort_keys=True))
    if args.expect_decision and decision.get("decision") != args.expect_decision:
        print(f"expected decision {args.expect_decision!r}, got {decision.get('decision')!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
