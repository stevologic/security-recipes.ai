#!/usr/bin/env python3
"""Generate the SecurityRecipes agent skill supply-chain pack.

Skills, rules files, hooks, and extensions sit between prompts and MCP
tools. They can encode multi-step behavior, file access, network egress,
memory writes, and shell execution. This generator turns the declared
skill model into a deterministic provenance, permission, and isolation
decision pack for enterprise agent-host admission.
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
DEFAULT_MODEL = Path("data/assurance/agent-skill-supply-chain-model.json")
DEFAULT_MANIFEST = Path("data/control-plane/workflow-manifests.json")
DEFAULT_CONTEXT_TRUST_PACK = Path("data/evidence/secure-context-trust-pack.json")
DEFAULT_MEMORY_BOUNDARY_PACK = Path("data/evidence/agent-memory-boundary-pack.json")
DEFAULT_CONNECTOR_TRUST_PACK = Path("data/evidence/mcp-connector-trust-pack.json")
DEFAULT_OUTPUT = Path("data/evidence/agent-skill-supply-chain-pack.json")

AST_RISKS = {f"AST{idx:02d}" for idx in range(1, 11)}
MCP_RISKS = {f"MCP{idx:02d}" for idx in range(1, 11)}
VALID_SCAN_STATUSES = {"pass", "warn", "fail", "missing"}
PRIVATE_DATA_CLASSES = {
    "private_key",
    "seed_phrase",
    "raw_access_token",
    "wallet_material",
    "browser_password",
    "production_credential",
}


class SkillSupplyChainError(RuntimeError):
    """Raised when the skill supply-chain pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SkillSupplyChainError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise SkillSupplyChainError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SkillSupplyChainError(f"{path} root must be a JSON object")
    return payload


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SkillSupplyChainError(f"{label} must be a list")
    return value


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SkillSupplyChainError(f"{label} must be an object")
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


def workflow_ids(manifest: dict[str, Any]) -> set[str]:
    return {
        str(workflow.get("id"))
        for workflow in as_list(manifest.get("workflows"), "manifest.workflows")
        if isinstance(workflow, dict) and workflow.get("id")
    }


def source_hash_or_declared(repo_root: Path, skill: dict[str, Any]) -> str:
    declared = str(skill.get("package_hash") or "").strip()
    source_path = str(skill.get("source_path") or "").strip()
    if source_path:
        path = repo_root / source_path
        if path.exists() and path.is_file():
            return "sha256:" + sha256_file(path)
    if declared:
        return declared
    return ""


def has_unrestricted_network(permissions: dict[str, Any]) -> bool:
    return any(str(item).strip() in {"*", "0.0.0.0/0", "internet"} for item in permissions.get("network_egress", []) or [])


def has_network(permissions: dict[str, Any]) -> bool:
    return bool(permissions.get("network_egress"))


def has_wide_read(permissions: dict[str, Any]) -> bool:
    patterns = [str(item).lower() for item in permissions.get("filesystem_read", []) or []]
    return any(pattern in {"~/**", "/**", "**/*", "*"} or pattern.startswith("~/") for pattern in patterns)


def has_private_read(permissions: dict[str, Any]) -> bool:
    patterns = [str(item).lower() for item in permissions.get("filesystem_read", []) or []]
    data_classes = {str(item) for item in permissions.get("data_access_classes", []) or []}
    sensitive_patterns = [".env", "*.pem", "*.key", "wallet", "browser", "password", "token", "secret"]
    return bool(data_classes.intersection(PRIVATE_DATA_CLASSES)) or any(
        marker in pattern for marker in sensitive_patterns for pattern in patterns
    )


def has_repo_write(permissions: dict[str, Any]) -> bool:
    writes = [str(item) for item in permissions.get("filesystem_write", []) or []]
    return bool(writes) and not has_identity_write(permissions)


def has_identity_write(permissions: dict[str, Any]) -> bool:
    if permissions.get("identity_file_write") is True:
        return True
    protected = {"agents.md", "claude.md", "soul.md", "memory.md", ".claude/", ".cursor/"}
    return any(
        any(marker in str(item).lower() for marker in protected)
        for item in permissions.get("filesystem_write", []) or []
    )


def mcp_access_modes(permissions: dict[str, Any]) -> set[str]:
    modes: set[str] = set()
    for row in permissions.get("mcp_namespaces", []) or []:
        if isinstance(row, dict) and row.get("access"):
            modes.add(str(row.get("access")))
    return modes


def risk_score(
    skill: dict[str, Any],
    weights: dict[str, Any],
    repo_root: Path,
) -> tuple[int, list[dict[str, Any]], bool]:
    permissions = as_dict(skill.get("permissions"), f"{skill.get('id')}.permissions")
    raw = 0
    factors: list[dict[str, Any]] = []

    def add(condition: bool, key: str, evidence: str) -> None:
        nonlocal raw
        if not condition:
            return
        points = int(weights.get(key, 0))
        raw += points
        factors.append({"id": key, "points": points, "evidence": evidence})

    add(bool(permissions.get("shell")), "shell_access", "skill declares shell access")
    add(has_unrestricted_network(permissions), "unrestricted_network_egress", "skill declares wildcard or unrestricted network egress")
    add(has_network(permissions) and not has_unrestricted_network(permissions), "domain_allowlisted_egress", "skill declares network egress domains")
    add(has_wide_read(permissions), "wide_filesystem_read", "skill can read broad local paths")
    add(has_private_read(permissions), "private_data_read", "skill can read private or credential-like data")
    add(has_repo_write(permissions), "repo_write", "skill can write repository or evidence files")
    add(has_identity_write(permissions), "identity_or_memory_write", "skill can write protected agent identity or memory files")
    add("read" in mcp_access_modes(permissions), "mcp_read", "skill uses read-only MCP namespaces")
    add(any(mode in {"write", "write_branch", "write_ticket", "approval_required"} for mode in mcp_access_modes(permissions)), "mcp_write", "skill uses write or approval-required MCP namespaces")
    add(bool(permissions.get("persistent_memory")), "persistent_memory", "skill persists memory or cross-session state")
    add(not skill.get("registry", {}).get("verified"), "untrusted_registry", "skill registry is not verified")
    add(not skill.get("publisher", {}).get("verified"), "unverified_publisher", "skill publisher is not verified")
    add(not skill.get("signature_present"), "missing_signature", "skill has no package signature")
    add(not source_hash_or_declared(repo_root, skill), "missing_hash", "skill has no package hash")
    add(not skill.get("version_pinned"), "unpinned_version", "skill is not version pinned")
    add(str(skill.get("scan_status")) != "pass", "failed_or_missing_scan", "skill scan status is not pass")
    add(bool(skill.get("cross_platform_reuse")), "cross_platform_reuse", "skill is reusable across agent hosts")

    credit_model = {}
    # Filled by caller through mutation-free recomputation below.
    lethal_trifecta = has_private_read(permissions) and has_network(permissions) and (
        bool(permissions.get("shell")) or has_identity_write(permissions) or bool(permissions.get("persistent_memory"))
    )
    return raw, factors, lethal_trifecta


def control_credits(skill: dict[str, Any], package_hash: str, credit_model: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    credits: list[dict[str, Any]] = []

    def add(condition: bool, credit_id: str, points: int, evidence: str) -> None:
        if condition:
            credits.append({"id": credit_id, "points": points, "evidence": evidence})

    add(bool(skill.get("publisher", {}).get("verified")), "verified_publisher", 8, "publisher identity is verified")
    add(bool(skill.get("signature_present")), "signed_package", 10, "package signature or maintained exception is present")
    add(bool(package_hash), "content_hash_pinned", 8, "package hash is pinned")
    add(bool(skill.get("version_pinned")), "version_pinned", 8, "version is pinned")
    add(bool(skill.get("sandbox_required")), "sandbox_required", 8, "sandbox profile is required")
    permissions = as_dict(skill.get("permissions"), f"{skill.get('id')}.permissions")
    add(has_network(permissions) and not has_unrestricted_network(permissions), "egress_allowlisted", 6, "network egress uses explicit domains")
    add(str(skill.get("scan_status")) == "pass", "scan_pass", 8, "scan status is pass")
    add(bool(skill.get("human_approval_required")), "human_approval_required", 6, "human approval is required for high-consequence paths")
    max_credit = int(credit_model.get("max_credit") or 46)
    total = min(max_credit, sum(int(item.get("points") or 0) for item in credits))
    return total, credits


def tier_for(model: dict[str, Any], residual_score: int) -> dict[str, Any]:
    for tier in model.get("risk_model", {}).get("risk_tiers", []) or []:
        if not isinstance(tier, dict):
            continue
        if int(tier.get("min_score", 0)) <= residual_score <= int(tier.get("max_score", 0)):
            return tier
    return {"id": "critical", "decision": "deny_untrusted_skill", "meaning": "No matching tier; fail closed."}


def next_actions(row: dict[str, Any]) -> list[str]:
    decision = str(row.get("decision"))
    actions: list[str] = []
    if row.get("lethal_trifecta"):
        actions.append("Block install and create incident evidence if observed in a live agent host.")
    if decision == "allow_pinned_readonly_skill":
        actions.append("Run under standard MCP gateway audit and context citation controls.")
    elif decision == "allow_guarded_skill":
        actions.append("Require sandbox profile, explicit egress allow-list, and run receipt evidence.")
    elif decision == "hold_for_skill_security_review":
        actions.append("Send to security-owner review before install, update, or workflow expansion.")
    else:
        actions.append("Deny install or runtime invocation until provenance and permission controls change.")
    if not row.get("package_hash"):
        actions.append("Require a package hash before treating the skill as installable.")
    if not row.get("signature_present"):
        actions.append("Require package signature or an expiring security exception.")
    return actions


def validate_model(model: dict[str, Any], manifest: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []
    require(model.get("schema_version") == "1.0", failures, "model schema_version must be 1.0")
    require(len(str(model.get("intent", ""))) >= 100, failures, "model intent must explain the product goal")
    standards = as_list(model.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 6, failures, "standards_alignment must include at least six references")
    seen_standards: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in seen_standards, failures, f"standards_alignment[{idx}].id duplicates {standard_id}")
        seen_standards.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")

    contract = as_dict(model.get("decision_contract"), "decision_contract")
    require(contract.get("default_decision") == "deny_unregistered_skill", failures, "decision contract must default deny unregistered skills")
    require(len(as_list(contract.get("prohibited_capabilities"), "decision_contract.prohibited_capabilities")) >= 8, failures, "prohibited capabilities must be specific")

    risk_model = as_dict(model.get("risk_model"), "risk_model")
    tiers = as_list(risk_model.get("risk_tiers"), "risk_model.risk_tiers")
    require({"low", "medium", "high", "critical"}.issubset({str(tier.get("id")) for tier in tiers if isinstance(tier, dict)}), failures, "risk tiers must include low, medium, high, critical")
    weights = as_dict(risk_model.get("risk_weights"), "risk_model.risk_weights")
    require(len(weights) >= 12, failures, "risk model must include supply-chain risk weights")
    credit_model = as_dict(risk_model.get("control_credits"), "risk_model.control_credits")
    require(int(credit_model.get("max_credit") or 0) > 0, failures, "control credit max_credit must be positive")

    known_workflows = workflow_ids(manifest)
    skills = as_list(model.get("skill_profiles"), "skill_profiles")
    require(len(skills) >= 4, failures, "at least four skill profiles are required")
    seen_skill_ids: set[str] = set()
    for idx, skill in enumerate(skills):
        item = as_dict(skill, f"skill_profiles[{idx}]")
        skill_id = str(item.get("id", "")).strip()
        require(bool(skill_id), failures, f"skill_profiles[{idx}].id is required")
        require(skill_id not in seen_skill_ids, failures, f"skill ID duplicates {skill_id}")
        seen_skill_ids.add(skill_id)
        require(bool(as_list(item.get("platforms"), f"{skill_id}.platforms")), failures, f"{skill_id}: platforms are required")
        require(str(item.get("scan_status")) in VALID_SCAN_STATUSES, failures, f"{skill_id}: scan_status is invalid")
        require(bool(as_dict(item.get("permissions"), f"{skill_id}.permissions")), failures, f"{skill_id}: permissions are required")
        ast_risks = {str(risk) for risk in as_list(item.get("mapped_ast_risks"), f"{skill_id}.mapped_ast_risks")}
        mcp_risks = {str(risk) for risk in as_list(item.get("mapped_mcp_risks"), f"{skill_id}.mapped_mcp_risks")}
        require(ast_risks.issubset(AST_RISKS), failures, f"{skill_id}: unknown AST risks {sorted(ast_risks - AST_RISKS)}")
        require(mcp_risks.issubset(MCP_RISKS), failures, f"{skill_id}: unknown MCP risks {sorted(mcp_risks - MCP_RISKS)}")
        missing_workflows = sorted({str(workflow_id) for workflow_id in item.get("allowed_workflow_ids", []) or []} - known_workflows)
        require(not missing_workflows, failures, f"{skill_id}: unknown allowed workflows {missing_workflows}")
        source_path = str(item.get("source_path") or "").strip()
        if source_path:
            require((repo_root / source_path).exists(), failures, f"{skill_id}: source_path does not exist: {source_path}")
    return failures


def validate_source_packs(
    context_trust_pack: dict[str, Any],
    memory_boundary_pack: dict[str, Any],
    connector_trust_pack: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    for label, payload in [
        ("secure context trust pack", context_trust_pack),
        ("agent memory boundary pack", memory_boundary_pack),
        ("connector trust pack", connector_trust_pack),
    ]:
        require(payload.get("schema_version") == "1.0", failures, f"{label} schema_version must be 1.0")
        failures_value = payload.get("failures")
        require(not failures_value, failures, f"{label} must have zero failures")
    return failures


def build_skill_rows(model: dict[str, Any], repo_root: Path) -> list[dict[str, Any]]:
    weights = as_dict(model.get("risk_model", {}).get("risk_weights"), "risk_model.risk_weights")
    credit_model = as_dict(model.get("risk_model", {}).get("control_credits"), "risk_model.control_credits")
    rows: list[dict[str, Any]] = []
    for skill in as_list(model.get("skill_profiles"), "skill_profiles"):
        item = as_dict(skill, "skill_profile")
        package_hash = source_hash_or_declared(repo_root, item)
        raw_score, factors, lethal_trifecta = risk_score(item, weights, repo_root)
        credit_score, credits = control_credits(item, package_hash, credit_model)
        residual_score = max(0, raw_score - credit_score)
        tier = tier_for(model, residual_score)
        decision = str(tier.get("decision"))
        permissions = as_dict(item.get("permissions"), f"{item.get('id')}.permissions")
        guarded_capability = (
            has_repo_write(permissions)
            or any(mode in {"write", "write_branch", "write_ticket", "approval_required"} for mode in mcp_access_modes(permissions))
            or bool(permissions.get("persistent_memory"))
            or bool(item.get("sandbox_required"))
            or bool(item.get("human_approval_required"))
        )
        if decision == "allow_pinned_readonly_skill" and guarded_capability:
            decision = "allow_guarded_skill"
        if lethal_trifecta:
            decision = "kill_session_on_malicious_skill_signal"
        elif decision == "deny_untrusted_skill" and not item.get("registry", {}).get("verified"):
            decision = "deny_untrusted_skill"
        row = {
            "allowed_workflow_ids": item.get("allowed_workflow_ids", []),
            "control_credit": credit_score,
            "control_credits": credits,
            "cross_platform_reuse": item.get("cross_platform_reuse"),
            "data_access_classes": permissions.get("data_access_classes", []),
            "decision": decision,
            "human_approval_required": item.get("human_approval_required"),
            "lethal_trifecta": lethal_trifecta,
            "mapped_ast_risks": item.get("mapped_ast_risks", []),
            "mapped_mcp_risks": item.get("mapped_mcp_risks", []),
            "network_egress": permissions.get("network_egress", []),
            "owner": item.get("owner", {}),
            "package_hash": package_hash,
            "permissions": permissions,
            "platforms": item.get("platforms", []),
            "publisher": item.get("publisher", {}),
            "raw_risk_score": raw_score,
            "registry": item.get("registry", {}),
            "required_controls": item.get("required_controls", []),
            "residual_risk_score": residual_score,
            "risk_factors": factors,
            "risk_tier": tier.get("id"),
            "risk_tier_meaning": tier.get("meaning"),
            "sandbox_required": item.get("sandbox_required"),
            "scan_status": item.get("scan_status"),
            "signature_present": item.get("signature_present"),
            "skill_id": item.get("id"),
            "source_path": item.get("source_path"),
            "title": item.get("title"),
            "version": item.get("version"),
            "version_pinned": item.get("version_pinned"),
        }
        row["next_actions"] = next_actions(row)
        rows.append(row)
    return sorted(rows, key=lambda row: (-int(row.get("residual_risk_score") or 0), str(row.get("skill_id"))))


def build_pack(
    *,
    model: dict[str, Any],
    manifest: dict[str, Any],
    model_path: Path,
    manifest_path: Path,
    context_trust_path: Path,
    memory_boundary_path: Path,
    connector_trust_path: Path,
    model_ref: Path,
    manifest_ref: Path,
    context_trust_ref: Path,
    memory_boundary_ref: Path,
    connector_trust_ref: Path,
    repo_root: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    rows = build_skill_rows(model, repo_root)
    decision_counts = Counter(str(row.get("decision")) for row in rows)
    tier_counts = Counter(str(row.get("risk_tier")) for row in rows)
    platform_counts = Counter(str(platform) for row in rows for platform in row.get("platforms", []))
    ast_counts = Counter(str(risk) for row in rows for risk in row.get("mapped_ast_risks", []))
    mcp_counts = Counter(str(risk) for row in rows for risk in row.get("mapped_mcp_risks", []))
    return {
        "decision_contract": model.get("decision_contract", {}),
        "enterprise_adoption_packet": model.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(model.get("last_reviewed", "")),
        "intent": model.get("intent"),
        "positioning": model.get("positioning", {}),
        "residual_risks": [
            {
                "risk": "The open pack models declared skills, not a live customer endpoint inventory.",
                "treatment": "Production deployments should ingest installed skill manifests, hashes, host versions, registry metadata, and gateway logs before enforcement."
            },
            {
                "risk": "Static manifest scanning cannot prove natural-language skill behavior is benign.",
                "treatment": "Pair this pack with semantic review, behavioral sandbox runs, red-team prompts, and runtime egress monitoring."
            },
            {
                "risk": "A skill can become unsafe after a publisher, dependency, registry, or host update.",
                "treatment": "Disable unpinned auto-updates and regenerate this pack whenever package hashes, permissions, scans, or host runtimes change."
            }
        ],
        "risk_model": model.get("risk_model", {}),
        "schema_version": PACK_SCHEMA_VERSION,
        "skill_supply_chain_summary": {
            "decision_counts": dict(sorted(decision_counts.items())),
            "failure_count": len(failures),
            "lethal_trifecta_count": sum(1 for row in rows if row.get("lethal_trifecta")),
            "platform_counts": dict(sorted(platform_counts.items())),
            "risk_tier_counts": dict(sorted(tier_counts.items())),
            "signed_skill_count": sum(1 for row in rows if row.get("signature_present")),
            "skill_count": len(rows),
            "top_risk_skills": [
                {
                    "decision": row.get("decision"),
                    "residual_risk_score": row.get("residual_risk_score"),
                    "risk_tier": row.get("risk_tier"),
                    "skill_id": row.get("skill_id"),
                    "title": row.get("title"),
                }
                for row in rows[:5]
            ],
            "verified_publisher_count": sum(1 for row in rows if row.get("publisher", {}).get("verified")),
            "workflow_count": len(workflow_ids(manifest)),
        },
        "source_artifacts": {
            "agent_skill_supply_chain_model": {
                "path": normalize_path(model_ref),
                "sha256": sha256_file(model_path),
            },
            "agent_memory_boundary_pack": {
                "path": normalize_path(memory_boundary_ref),
                "sha256": sha256_file(memory_boundary_path),
            },
            "mcp_connector_trust_pack": {
                "path": normalize_path(connector_trust_ref),
                "sha256": sha256_file(connector_trust_path),
            },
            "secure_context_trust_pack": {
                "path": normalize_path(context_trust_ref),
                "sha256": sha256_file(context_trust_path),
            },
            "workflow_manifest": {
                "path": normalize_path(manifest_ref),
                "sha256": sha256_file(manifest_path),
            },
        },
        "standards_alignment": model.get("standards_alignment", []),
        "risk_coverage": {
            "ast_risk_counts": dict(sorted(ast_counts.items())),
            "mcp_risk_counts": dict(sorted(mcp_counts.items())),
        },
        "skill_profiles": rows,
    }


def validate_pack(pack: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(pack.get("schema_version") == PACK_SCHEMA_VERSION, failures, "pack schema_version must be 1.0")
    rows = as_list(pack.get("skill_profiles"), "skill_profiles")
    summary = as_dict(pack.get("skill_supply_chain_summary"), "skill_supply_chain_summary")
    require(summary.get("skill_count") == len(rows), failures, "skill summary count is stale")
    require(summary.get("lethal_trifecta_count") == sum(1 for row in rows if isinstance(row, dict) and row.get("lethal_trifecta")), failures, "lethal trifecta count is stale")
    for row in rows:
        item = as_dict(row, "skill_profile")
        skill_id = str(item.get("skill_id"))
        require(item.get("decision") in {
            "allow_pinned_readonly_skill",
            "allow_guarded_skill",
            "hold_for_skill_security_review",
            "deny_untrusted_skill",
            "deny_unregistered_skill",
            "kill_session_on_malicious_skill_signal",
        }, failures, f"{skill_id}: decision is invalid")
        require(int(item.get("residual_risk_score", -1)) == max(0, int(item.get("raw_risk_score", 0)) - int(item.get("control_credit", 0))), failures, f"{skill_id}: residual risk score is stale")
        require(bool(item.get("next_actions")), failures, f"{skill_id}: next actions are required")
        if item.get("decision") in {"allow_pinned_readonly_skill", "allow_guarded_skill"}:
            require(bool(item.get("package_hash")), failures, f"{skill_id}: allowed skill must have package hash")
    return failures


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--context-trust-pack", type=Path, default=DEFAULT_CONTEXT_TRUST_PACK)
    parser.add_argument("--memory-boundary-pack", type=Path, default=DEFAULT_MEMORY_BOUNDARY_PACK)
    parser.add_argument("--connector-trust-pack", type=Path, default=DEFAULT_CONNECTOR_TRUST_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in skill supply-chain pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    model_path = resolve(repo_root, args.model)
    manifest_path = resolve(repo_root, args.manifest)
    context_trust_path = resolve(repo_root, args.context_trust_pack)
    memory_boundary_path = resolve(repo_root, args.memory_boundary_pack)
    connector_trust_path = resolve(repo_root, args.connector_trust_pack)
    output_path = resolve(repo_root, args.output)

    try:
        model = load_json(model_path)
        manifest = load_json(manifest_path)
        context_trust_pack = load_json(context_trust_path)
        memory_boundary_pack = load_json(memory_boundary_path)
        connector_trust_pack = load_json(connector_trust_path)
        failures = validate_model(model, manifest, repo_root)
        failures.extend(validate_source_packs(context_trust_pack, memory_boundary_pack, connector_trust_pack))
        pack = build_pack(
            model=model,
            manifest=manifest,
            model_path=model_path,
            manifest_path=manifest_path,
            context_trust_path=context_trust_path,
            memory_boundary_path=memory_boundary_path,
            connector_trust_path=connector_trust_path,
            model_ref=args.model,
            manifest_ref=args.manifest,
            context_trust_ref=args.context_trust_pack,
            memory_boundary_ref=args.memory_boundary_pack,
            connector_trust_ref=args.connector_trust_pack,
            repo_root=repo_root,
            generated_at=args.generated_at,
            failures=failures,
        )
        failures.extend(validate_pack(pack))
        pack["failures"] = failures
        pack["skill_supply_chain_summary"]["failure_count"] = len(failures)
    except SkillSupplyChainError as exc:
        print(f"agent skill supply-chain pack generation failed: {exc}", file=sys.stderr)
        return 1

    next_text = stable_json(pack)
    if args.check:
        if failures:
            print("agent skill supply-chain pack validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current_text = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run this script without --check", file=sys.stderr)
            return 1
        if current_text != next_text:
            print(f"{output_path} is stale; run scripts/generate_agent_skill_supply_chain_pack.py", file=sys.stderr)
            return 1
        print(f"Validated agent skill supply-chain pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(next_text, encoding="utf-8")
    if failures:
        print("Generated agent skill supply-chain pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Generated agent skill supply-chain pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
