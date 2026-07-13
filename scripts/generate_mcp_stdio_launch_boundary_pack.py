#!/usr/bin/env python3
"""Generate the SecurityRecipes MCP STDIO launch boundary pack.

STDIO MCP servers are local subprocesses. That makes an MCP client
configuration equivalent to an executable launch request, not only a
tool registration. This generator turns the source launch model into a
machine-readable pack that enterprise agent hosts can use before they
spawn a local MCP server.
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
DEFAULT_MODEL = Path("data/assurance/mcp-stdio-launch-boundary-model.json")
DEFAULT_CONNECTOR_INTAKE_PACK = Path("data/evidence/mcp-connector-intake-pack.json")
DEFAULT_MCP_SERVER = Path("mcp_server.py")
DEFAULT_OUTPUT = Path("data/evidence/mcp-stdio-launch-boundary-pack.json")

REQUIRED_DECISIONS = {
    "allow_pinned_sandboxed_stdio_launch",
    "hold_for_owner_review",
    "deny_unregistered_stdio_launch",
    "deny_untrusted_package_launch",
    "deny_shell_or_network_bootstrap",
    "kill_session_on_secret_or_privilege_request",
}
REQUIRED_PROFILES = {
    "pinned-readonly-python-module",
    "pinned-node-package-stdio",
    "containerized-stdio-server",
    "package-runner-bootstrap",
    "shell-bootstrap",
}


class StdioLaunchBoundaryError(RuntimeError):
    """Raised when the STDIO launch boundary pack cannot be generated."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise StdioLaunchBoundaryError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise StdioLaunchBoundaryError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise StdioLaunchBoundaryError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StdioLaunchBoundaryError(f"{label} must be an object")
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise StdioLaunchBoundaryError(f"{label} must be a list")
    return value


def stable_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def normalize_path(path: Path) -> str:
    return path.as_posix()


def resolve(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def normalize_executable(command: str) -> str:
    name = Path(str(command).replace("\\", "/")).name.lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def validate_model(model: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    require(model.get("schema_version") == PACK_SCHEMA_VERSION, failures, "model schema_version must be 1.0")
    require(len(str(model.get("intent", ""))) >= 100, failures, "model intent must explain the product goal")

    standards = as_list(model.get("standards_alignment"), "standards_alignment")
    require(len(standards) >= 7, failures, "standards_alignment must include current MCP, agentic, and AI security references")
    standard_ids: set[str] = set()
    for idx, standard in enumerate(standards):
        item = as_dict(standard, f"standards_alignment[{idx}]")
        standard_id = str(item.get("id", "")).strip()
        require(bool(standard_id), failures, f"standards_alignment[{idx}].id is required")
        require(standard_id not in standard_ids, failures, f"{standard_id}: duplicated standard id")
        standard_ids.add(standard_id)
        require(str(item.get("url", "")).startswith("https://"), failures, f"{standard_id}: url must be https")
        require(len(str(item.get("coverage", ""))) >= 60, failures, f"{standard_id}: coverage must be specific")

    contract = as_dict(model.get("decision_contract"), "decision_contract")
    require(contract.get("default_state") == "deny_unregistered_stdio_launch", failures, "decision_contract must deny unknown launches")
    decisions = {
        str(item.get("decision"))
        for item in as_list(contract.get("decisions"), "decision_contract.decisions")
        if isinstance(item, dict)
    }
    require(REQUIRED_DECISIONS.issubset(decisions), failures, "decision_contract must declare every STDIO launch decision")
    require(len(as_list(contract.get("runtime_fields"), "decision_contract.runtime_fields")) >= 15, failures, "runtime_fields are incomplete")
    for field in [
        "required_allow_controls",
        "package_runners",
        "prohibited_executables",
        "dangerous_arg_markers",
        "forbidden_env_key_markers",
        "prohibited_data_classes",
        "high_impact_capabilities",
    ]:
        require(bool(as_list(contract.get(field), f"decision_contract.{field}")), failures, f"decision_contract.{field} must not be empty")

    profiles = as_list(model.get("launch_profiles"), "launch_profiles")
    profile_ids = {str(item.get("id")) for item in profiles if isinstance(item, dict)}
    require(REQUIRED_PROFILES.issubset(profile_ids), failures, "launch_profiles must include all required STDIO profile families")
    for idx, profile in enumerate(profiles):
        item = as_dict(profile, f"launch_profiles[{idx}]")
        profile_id = str(item.get("id", "")).strip()
        require(bool(profile_id), failures, f"launch_profiles[{idx}].id is required")
        require(str(item.get("default_decision")) in REQUIRED_DECISIONS, failures, f"{profile_id}: default_decision is invalid")
        require(bool(as_list(item.get("allowed_executables"), f"{profile_id}.allowed_executables")), failures, f"{profile_id}: allowed_executables are required")
        require(bool(as_list(item.get("required_controls"), f"{profile_id}.required_controls")), failures, f"{profile_id}: required_controls are required")

    launches = as_list(model.get("approved_launches"), "approved_launches")
    require(len(launches) >= 3, failures, "approved_launches must include realistic allow, hold, and deny examples")
    launch_ids: set[str] = set()
    for idx, launch in enumerate(launches):
        item = as_dict(launch, f"approved_launches[{idx}]")
        launch_id = str(item.get("launch_id", "")).strip()
        profile_id = str(item.get("profile_id", "")).strip()
        require(bool(launch_id), failures, f"approved_launches[{idx}].launch_id is required")
        require(launch_id not in launch_ids, failures, f"{launch_id}: duplicated launch_id")
        launch_ids.add(launch_id)
        require(profile_id in profile_ids, failures, f"{launch_id}: unknown profile_id {profile_id}")
        require(str(item.get("transport")) == "stdio", failures, f"{launch_id}: transport must be stdio")
        require(str(item.get("command", "")).strip(), failures, f"{launch_id}: command is required")
        require(isinstance(item.get("args"), list), failures, f"{launch_id}: args must be a list")
        require(isinstance(item.get("allowed_env_keys"), list), failures, f"{launch_id}: allowed_env_keys must be a list")
        require(isinstance(item.get("allowed_external_hosts"), list), failures, f"{launch_id}: allowed_external_hosts must be a list")
        require(isinstance(item.get("filesystem_roots"), list), failures, f"{launch_id}: filesystem_roots must be a list")
        require(bool(as_list(item.get("approved_controls"), f"{launch_id}.approved_controls")), failures, f"{launch_id}: approved_controls are required")
        require(str(item.get("default_decision")) in REQUIRED_DECISIONS, failures, f"{launch_id}: default_decision is invalid")
        owner = as_dict(item.get("owner"), f"{launch_id}.owner")
        require(str(owner.get("accountable_team", "")).strip(), failures, f"{launch_id}: owner.accountable_team is required")
        require(str(owner.get("escalation", "")).strip(), failures, f"{launch_id}: owner.escalation is required")

    drills = as_list(model.get("red_team_drills"), "red_team_drills")
    require(len(drills) >= 4, failures, "red_team_drills must cover shell, secret, package, network, and approval attacks")
    for idx, drill in enumerate(drills):
        item = as_dict(drill, f"red_team_drills[{idx}]")
        require(str(item.get("expected_decision")) in REQUIRED_DECISIONS, failures, f"red_team_drills[{idx}].expected_decision is invalid")

    return failures


def connector_intake_by_candidate_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(candidate.get("candidate_id")): candidate
        for candidate in pack.get("candidate_evaluations", [])
        if isinstance(candidate, dict) and candidate.get("candidate_id")
    }


def finding(finding_id: str, severity: str, title: str, evidence: str, control: str) -> dict[str, str]:
    return {
        "control": control,
        "evidence": evidence,
        "id": finding_id,
        "severity": severity,
        "title": title,
    }


def launch_findings(
    launch: dict[str, Any],
    profile: dict[str, Any],
    contract: dict[str, Any],
    intake_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    controls = {str(control) for control in launch.get("approved_controls", [])}
    required_controls = {str(control) for control in profile.get("required_controls", [])}
    executable = normalize_executable(str(launch.get("command", "")))
    package_runners = {str(item) for item in contract.get("package_runners", [])}
    prohibited_executables = {str(item) for item in contract.get("prohibited_executables", [])}
    high_impact = {str(item) for item in contract.get("high_impact_capabilities", [])}
    capabilities = {str(item) for item in launch.get("requested_capabilities", [])}

    if executable in prohibited_executables or str(profile.get("id")) == "shell-bootstrap":
        findings.append(
            finding(
                "shell-bootstrap-command",
                "critical",
                "STDIO launch uses a shell or prohibited bootstrap executable",
                str(launch.get("command")),
                "exact_command_allowlist",
            )
        )
    if executable in package_runners and launch.get("package_install_on_launch"):
        findings.append(
            finding(
                "package-install-on-launch",
                "critical",
                "STDIO launch can resolve or install package code at startup",
                f"{launch.get('command')} {' '.join(str(arg) for arg in launch.get('args', []))}",
                "package_digest_pin",
            )
        )
    if "*" in {str(host) for host in launch.get("allowed_external_hosts", [])}:
        findings.append(
            finding(
                "wildcard-network-egress",
                "high",
                "STDIO launch declares wildcard network egress",
                ",".join(str(host) for host in launch.get("allowed_external_hosts", [])),
                "network_egress_policy",
            )
        )
    if launch.get("allows_private_network"):
        findings.append(
            finding(
                "private-network-reachable",
                "high",
                "STDIO launch can reach private network ranges",
                str(launch.get("namespace")),
                "network_egress_policy",
            )
        )
    if (capabilities & high_impact) and "approval_receipt_for_high_impact" not in controls:
        findings.append(
            finding(
                "high-impact-without-approval",
                "high",
                "High-impact local capability lacks approval receipt control",
                ",".join(sorted(capabilities & high_impact)),
                "approval_receipt_for_high_impact",
            )
        )

    missing_controls = sorted(required_controls - controls)
    if missing_controls:
        findings.append(
            finding(
                "missing-launch-controls",
                "medium",
                "STDIO launch profile required controls are missing",
                ",".join(missing_controls),
                "profile_required_controls",
            )
        )

    source_candidate_id = launch.get("source_candidate_id")
    if source_candidate_id and source_candidate_id in intake_by_id:
        candidate = intake_by_id[str(source_candidate_id)]
        decision = str(candidate.get("intake_decision"))
        if decision in {"hold_for_controls", "deny_until_redesigned"}:
            findings.append(
                finding(
                    "connector-intake-not-approved",
                    "high" if decision == "hold_for_controls" else "critical",
                    "Source connector intake decision is not approved",
                    f"{source_candidate_id}:{decision}",
                    "connector_intake_gate",
                )
            )

    return sorted(
        findings,
        key=lambda row: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(row["severity"], 4), row["id"]),
    )


def computed_decision(launch: dict[str, Any], profile: dict[str, Any], findings: list[dict[str, str]]) -> str:
    launch_default = str(launch.get("default_decision") or profile.get("default_decision"))
    finding_ids = {finding["id"] for finding in findings}
    critical_ids = {finding["id"] for finding in findings if finding["severity"] == "critical"}

    if "shell-bootstrap-command" in critical_ids:
        return "deny_shell_or_network_bootstrap"
    if "package-install-on-launch" in critical_ids:
        return "deny_untrusted_package_launch"
    if "connector-intake-not-approved" in critical_ids:
        return "deny_untrusted_package_launch"
    if launch_default.startswith("deny_"):
        return launch_default
    if {"wildcard-network-egress", "private-network-reachable"} & finding_ids:
        return "deny_shell_or_network_bootstrap"
    if findings:
        return "hold_for_owner_review"
    return launch_default


def build_launch_boundaries(
    model: dict[str, Any],
    connector_intake_pack: dict[str, Any],
) -> list[dict[str, Any]]:
    profiles = {
        str(profile.get("id")): profile
        for profile in model.get("launch_profiles", [])
        if isinstance(profile, dict) and profile.get("id")
    }
    intake_by_id = connector_intake_by_candidate_id(connector_intake_pack)
    contract = model.get("decision_contract", {}) if isinstance(model.get("decision_contract"), dict) else {}
    rows: list[dict[str, Any]] = []
    for launch in model.get("approved_launches", []):
        if not isinstance(launch, dict):
            continue
        profile = profiles.get(str(launch.get("profile_id")), {})
        findings = launch_findings(launch, profile, contract, intake_by_id)
        required_controls = {str(control) for control in profile.get("required_controls", [])}
        approved_controls = {str(control) for control in launch.get("approved_controls", [])}
        rows.append(
            {
                "allowed_env_key_prefixes": launch.get("allowed_env_key_prefixes", []),
                "allowed_env_keys": launch.get("allowed_env_keys", []),
                "allowed_external_hosts": launch.get("allowed_external_hosts", []),
                "allows_private_network": launch.get("allows_private_network"),
                "approved_controls": sorted(approved_controls),
                "args": launch.get("args", []),
                "command": launch.get("command"),
                "computed_decision": computed_decision(launch, profile, findings),
                "connector_id": launch.get("connector_id"),
                "control_gaps": sorted(required_controls - approved_controls),
                "default_decision": launch.get("default_decision"),
                "evidence": launch.get("evidence", []),
                "filesystem_roots": launch.get("filesystem_roots", []),
                "launch_hash": stable_hash(launch),
                "launch_id": launch.get("launch_id"),
                "namespace": launch.get("namespace"),
                "owner": launch.get("owner", {}),
                "package_hash_required": launch.get("package_hash_required"),
                "package_install_on_launch": launch.get("package_install_on_launch"),
                "package_name": launch.get("package_name"),
                "package_version": launch.get("package_version"),
                "profile_id": launch.get("profile_id"),
                "requested_capabilities": launch.get("requested_capabilities", []),
                "risk_findings": findings,
                "source_candidate_id": launch.get("source_candidate_id"),
                "source_provenance": launch.get("source_provenance"),
                "title": launch.get("title"),
                "transport": launch.get("transport"),
            }
        )
    return sorted(rows, key=lambda row: str(row.get("launch_id")))


def build_profile_rows(model: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for profile in model.get("launch_profiles", []):
        if not isinstance(profile, dict):
            continue
        rows.append(
            {
                "allowed_executables": profile.get("allowed_executables", []),
                "default_decision": profile.get("default_decision"),
                "default_filesystem_mode": profile.get("default_filesystem_mode"),
                "default_network_egress": profile.get("default_network_egress"),
                "description": profile.get("description"),
                "package_install_allowed": profile.get("package_install_allowed"),
                "profile_hash": stable_hash(profile),
                "profile_id": profile.get("id"),
                "required_controls": profile.get("required_controls", []),
                "title": profile.get("title"),
            }
        )
    return sorted(rows, key=lambda row: str(row.get("profile_id")))


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    decisions = Counter(str(row.get("computed_decision")) for row in rows)
    profiles = Counter(str(row.get("profile_id")) for row in rows)
    return {
        "allow_count": decisions.get("allow_pinned_sandboxed_stdio_launch", 0),
        "decision_counts": dict(sorted(decisions.items())),
        "deny_or_kill_count": sum(
            decisions.get(decision, 0)
            for decision in [
                "deny_unregistered_stdio_launch",
                "deny_untrusted_package_launch",
                "deny_shell_or_network_bootstrap",
                "kill_session_on_secret_or_privilege_request",
            ]
        ),
        "launch_count": len(rows),
        "profile_counts": dict(sorted(profiles.items())),
        "registered_stdio_launch_count": len(rows),
    }


def build_pack(
    *,
    model: dict[str, Any],
    connector_intake_pack: dict[str, Any],
    model_path: Path,
    connector_intake_pack_path: Path,
    mcp_server_path: Path,
    model_ref: Path,
    connector_intake_pack_ref: Path,
    mcp_server_ref: Path,
    generated_at: str | None,
    failures: list[str],
) -> dict[str, Any]:
    launches = build_launch_boundaries(model, connector_intake_pack)
    return {
        "decision_contract": model.get("decision_contract", {}),
        "enterprise_adoption_packet": model.get("enterprise_adoption_packet", {}),
        "failures": failures,
        "generated_at": generated_at or str(model.get("last_reviewed", "")),
        "intent": model.get("intent"),
        "launch_boundaries": launches,
        "launch_profiles": build_profile_rows(model),
        "positioning": model.get("positioning", {}),
        "red_team_drills": model.get("red_team_drills", []),
        "schema_version": PACK_SCHEMA_VERSION,
        "source_artifacts": {
            "connector_intake_pack": {
                "path": normalize_path(connector_intake_pack_ref),
                "sha256": sha256_file(connector_intake_pack_path),
            },
            "mcp_server": {
                "path": normalize_path(mcp_server_ref),
                "sha256": sha256_file(mcp_server_path),
            },
            "stdio_launch_boundary_model": {
                "path": normalize_path(model_ref),
                "sha256": sha256_file(model_path),
            },
        },
        "standards_alignment": model.get("standards_alignment", []),
        "stdio_launch_summary": build_summary(launches),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--connector-intake-pack", type=Path, default=DEFAULT_CONNECTOR_INTAKE_PACK)
    parser.add_argument("--mcp-server", type=Path, default=DEFAULT_MCP_SERVER)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in STDIO launch boundary pack is stale.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    model_path = resolve(repo_root, args.model)
    connector_intake_pack_path = resolve(repo_root, args.connector_intake_pack)
    mcp_server_path = resolve(repo_root, args.mcp_server)
    output_path = resolve(repo_root, args.output)

    try:
        model = load_json(model_path)
        connector_intake_pack = load_json(connector_intake_pack_path)
        failures = validate_model(model)
        require(connector_intake_pack.get("schema_version") == PACK_SCHEMA_VERSION, failures, "connector intake pack schema_version must be 1.0")
        require(mcp_server_path.exists(), failures, f"MCP server source path does not exist: {args.mcp_server}")
        pack = build_pack(
            model=model,
            connector_intake_pack=connector_intake_pack,
            model_path=model_path,
            connector_intake_pack_path=connector_intake_pack_path,
            mcp_server_path=mcp_server_path,
            model_ref=args.model,
            connector_intake_pack_ref=args.connector_intake_pack,
            mcp_server_ref=args.mcp_server,
            generated_at=args.generated_at,
            failures=failures,
        )
    except StdioLaunchBoundaryError as exc:
        print(f"MCP STDIO launch boundary generation failed: {exc}", file=sys.stderr)
        return 1

    rendered = stable_json(pack)
    if args.check:
        if failures:
            print("MCP STDIO launch boundary validation failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        try:
            current = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{output_path} is missing; run scripts/generate_mcp_stdio_launch_boundary_pack.py", file=sys.stderr)
            return 1
        if current != rendered:
            print(f"{output_path} is stale; run scripts/generate_mcp_stdio_launch_boundary_pack.py", file=sys.stderr)
            return 1
        print(f"Validated MCP STDIO launch boundary pack: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")

    if failures:
        print("Generated MCP STDIO launch boundary pack with validation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Generated MCP STDIO launch boundary pack: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
