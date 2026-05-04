#!/usr/bin/env python3
"""Evaluate one MCP STDIO launch decision.

The evaluator is designed for MCP clients, endpoint policy agents, and
CI gates that need a deterministic answer before spawning a local MCP
server subprocess.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_STDIO_LAUNCH_PACK = Path("data/evidence/mcp-stdio-launch-boundary-pack.json")

ALLOW_DECISIONS = {"allow_pinned_sandboxed_stdio_launch"}
VALID_DECISIONS = {
    *ALLOW_DECISIONS,
    "hold_for_owner_review",
    "deny_unregistered_stdio_launch",
    "deny_untrusted_package_launch",
    "deny_shell_or_network_bootstrap",
    "kill_session_on_secret_or_privilege_request",
}


class StdioLaunchDecisionError(RuntimeError):
    """Raised when the pack or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise StdioLaunchDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise StdioLaunchDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise StdioLaunchDecisionError(f"{path} root must be a JSON object")
    return payload


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def lower_set(values: Any) -> set[str]:
    return {str(item).strip().lower() for item in as_list(values) if str(item).strip()}


def launches_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(launch.get("launch_id")): launch
        for launch in as_list(pack.get("launch_boundaries"))
        if isinstance(launch, dict) and launch.get("launch_id")
    }


def profiles_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(profile.get("profile_id")): profile
        for profile in as_list(pack.get("launch_profiles"))
        if isinstance(profile, dict) and profile.get("profile_id")
    }


def normalize_executable(command: str | None) -> str:
    if not command:
        return ""
    name = Path(str(command).replace("\\", "/")).name.lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def contains_marker(values: Any, markers: Any) -> str | None:
    marker_values = [str(marker).lower() for marker in as_list(markers) if str(marker)]
    for value in as_list(values):
        text = str(value).lower()
        for marker in marker_values:
            if marker and marker in text:
                return marker
    return None


def env_key_violation(env_keys: Any, markers: Any, allowed_keys: Any, allowed_prefixes: Any) -> str | None:
    allowed = {str(item).strip() for item in as_list(allowed_keys) if str(item).strip()}
    prefixes = [str(item).strip() for item in as_list(allowed_prefixes) if str(item).strip()]
    marker_values = [str(marker).lower() for marker in as_list(markers) if str(marker).strip()]
    for key in as_list(env_keys):
        item = str(key).strip()
        if not item:
            continue
        if item in allowed or any(item.startswith(prefix) for prefix in prefixes):
            continue
        item_lower = item.lower()
        if any(marker in item_lower for marker in marker_values):
            return item
    return None


def has_approval(value: Any) -> bool:
    record = as_dict(value)
    if not record:
        return False
    status = str(record.get("status") or record.get("decision") or "").lower()
    return bool(record.get("approval_id") or record.get("id")) and status in {"approved", "allow", "granted"}


def decision_result(
    *,
    decision: str,
    reason: str,
    runtime_request: dict[str, Any],
    violations: list[str] | None = None,
    matched_launch: dict[str, Any] | None = None,
    matched_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise StdioLaunchDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision in ALLOW_DECISIONS,
        "decision": decision,
        "matched_launch": {
            "computed_decision": matched_launch.get("computed_decision") if matched_launch else None,
            "launch_id": matched_launch.get("launch_id") if matched_launch else runtime_request.get("launch_id"),
            "namespace": matched_launch.get("namespace") if matched_launch else None,
            "title": matched_launch.get("title") if matched_launch else None,
        },
        "matched_profile": {
            "profile_id": matched_profile.get("profile_id") if matched_profile else None,
            "title": matched_profile.get("title") if matched_profile else None,
        },
        "reason": reason,
        "runtime_request": {
            "agent_id": runtime_request.get("agent_id"),
            "args": as_list(runtime_request.get("args")),
            "command": runtime_request.get("command"),
            "correlation_id": runtime_request.get("correlation_id"),
            "env_keys": as_list(runtime_request.get("env_keys")),
            "launch_id": runtime_request.get("launch_id"),
            "network_egress": runtime_request.get("network_egress"),
            "package_hash": runtime_request.get("package_hash"),
            "package_install_on_launch": runtime_request.get("package_install_on_launch"),
            "package_name": runtime_request.get("package_name"),
            "package_version": runtime_request.get("package_version"),
            "requested_capabilities": as_list(runtime_request.get("requested_capabilities")),
            "run_id": runtime_request.get("run_id"),
            "sandboxed": runtime_request.get("sandboxed"),
        },
        "violations": violations or [],
    }


def evaluate_mcp_stdio_launch_decision(
    launch_pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured STDIO launch decision."""
    if not isinstance(launch_pack, dict):
        raise StdioLaunchDecisionError("launch_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise StdioLaunchDecisionError("runtime_request must be an object")

    if runtime_request.get("runtime_kill_signal"):
        return decision_result(
            decision="kill_session_on_secret_or_privilege_request",
            reason="runtime kill signal was raised before STDIO launch",
            runtime_request=runtime_request,
            violations=[str(runtime_request.get("runtime_kill_signal"))],
        )

    launch_id = str(runtime_request.get("launch_id") or "").strip()
    launch = launches_by_id(launch_pack).get(launch_id)
    if not launch:
        return decision_result(
            decision="deny_unregistered_stdio_launch",
            reason="STDIO launch is not registered in the launch boundary pack",
            runtime_request=runtime_request,
            violations=[f"unknown launch_id: {launch_id or '<missing>'}"],
        )

    profile = profiles_by_id(launch_pack).get(str(launch.get("profile_id")))
    if not profile:
        return decision_result(
            decision="deny_unregistered_stdio_launch",
            reason="registered STDIO launch references an unknown profile",
            runtime_request=runtime_request,
            matched_launch=launch,
            violations=[f"unknown profile_id: {launch.get('profile_id')}"],
        )

    contract = as_dict(launch_pack.get("decision_contract"))
    expected_command = normalize_executable(str(launch.get("command") or ""))
    actual_command = normalize_executable(str(runtime_request.get("command") or ""))
    if not actual_command:
        return decision_result(
            decision="hold_for_owner_review",
            reason="runtime launch request omitted the command that will execute",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=["command is required"],
        )
    if actual_command != expected_command:
        return decision_result(
            decision="deny_shell_or_network_bootstrap",
            reason="runtime command does not match the registered exact command allowlist",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=[f"expected {expected_command}, got {actual_command}"],
        )

    runtime_args = [str(arg) for arg in as_list(runtime_request.get("args"))]
    expected_args = [str(arg) for arg in as_list(launch.get("args"))]
    if runtime_args != expected_args:
        marker = contains_marker(runtime_args, contract.get("dangerous_arg_markers"))
        decision = "deny_shell_or_network_bootstrap" if marker else "hold_for_owner_review"
        return decision_result(
            decision=decision,
            reason="runtime arguments do not match the registered launch boundary",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=[f"argument drift from registered args; marker={marker or 'none'}"],
        )

    prohibited_executables = {str(item) for item in as_list(contract.get("prohibited_executables"))}
    if actual_command in prohibited_executables or str(profile.get("profile_id")) == "shell-bootstrap":
        return decision_result(
            decision="deny_shell_or_network_bootstrap",
            reason="STDIO launch uses a shell or prohibited bootstrap executable",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=[actual_command],
        )

    marker = contains_marker(runtime_args, contract.get("dangerous_arg_markers"))
    if marker:
        return decision_result(
            decision="deny_shell_or_network_bootstrap",
            reason="STDIO launch arguments contain command chaining or network bootstrap markers",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=[f"dangerous marker: {marker}"],
        )

    env_keys = as_list(runtime_request.get("env_keys"))
    if runtime_request.get("contains_secret") or runtime_request.get("env_contains_secret"):
        return decision_result(
            decision="kill_session_on_secret_or_privilege_request",
            reason="STDIO launch attempted to expose secret material to a local process",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=["contains_secret=true"],
        )
    env_violation = env_key_violation(
        env_keys,
        contract.get("forbidden_env_key_markers"),
        launch.get("allowed_env_keys"),
        launch.get("allowed_env_key_prefixes"),
    )
    if env_violation:
        return decision_result(
            decision="kill_session_on_secret_or_privilege_request",
            reason="STDIO launch environment includes an unapproved secret-like key",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=[env_violation],
        )

    if runtime_request.get("run_as_root") or runtime_request.get("requests_privilege_escalation"):
        return decision_result(
            decision="kill_session_on_secret_or_privilege_request",
            reason="STDIO launch requested privileged local execution",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=["privilege escalation requested"],
        )

    data_classes = lower_set(runtime_request.get("data_classes"))
    prohibited_data = lower_set(contract.get("prohibited_data_classes"))
    if data_classes & prohibited_data:
        return decision_result(
            decision="kill_session_on_secret_or_privilege_request",
            reason="STDIO launch attempted to expose prohibited data classes",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=[f"prohibited data class: {item}" for item in sorted(data_classes & prohibited_data)],
        )

    package_runners = {str(item) for item in as_list(contract.get("package_runners"))}
    package_install = bool(runtime_request.get("package_install_on_launch") or launch.get("package_install_on_launch"))
    if actual_command in package_runners and package_install:
        trusted_package = (
            bool(runtime_request.get("package_hash"))
            and bool(runtime_request.get("signature_present"))
            and bool(runtime_request.get("publisher_verified"))
        )
        if not trusted_package:
            return decision_result(
                decision="deny_untrusted_package_launch",
                reason="package-runner STDIO launch lacks digest, signature, or verified publisher evidence",
                runtime_request=runtime_request,
                matched_launch=launch,
                matched_profile=profile,
                violations=["package_hash, signature_present, and publisher_verified are required"],
            )

    if runtime_request.get("allows_private_network") or str(runtime_request.get("network_egress") or "").lower() in {"*", "any", "unrestricted"}:
        return decision_result(
            decision="deny_shell_or_network_bootstrap",
            reason="STDIO launch requested broad or private-network egress",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=["network egress is not narrowed"],
        )

    allowed_hosts = {str(host) for host in as_list(runtime_request.get("allowed_external_hosts"))}
    if "*" in allowed_hosts:
        return decision_result(
            decision="deny_shell_or_network_bootstrap",
            reason="STDIO launch requested wildcard external host access",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=["allowed_external_hosts contains *"],
        )

    if not runtime_request.get("sandboxed"):
        return decision_result(
            decision="hold_for_owner_review",
            reason="STDIO launch is missing sandbox evidence",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=["sandboxed=false"],
        )

    capabilities = lower_set(runtime_request.get("requested_capabilities")) | lower_set(launch.get("requested_capabilities"))
    high_impact = lower_set(contract.get("high_impact_capabilities"))
    if (capabilities & high_impact) and not has_approval(runtime_request.get("human_approval_record")):
        return decision_result(
            decision="hold_for_owner_review",
            reason="high-impact local capability requires typed owner approval",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=[f"approval required for: {item}" for item in sorted(capabilities & high_impact)],
        )

    computed = str(launch.get("computed_decision") or launch.get("default_decision") or profile.get("default_decision"))
    if computed != "allow_pinned_sandboxed_stdio_launch":
        return decision_result(
            decision=computed if computed in VALID_DECISIONS else "hold_for_owner_review",
            reason="registered STDIO launch boundary is not in an allow state",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=[f"computed_decision={computed}"],
        )

    return decision_result(
        decision="allow_pinned_sandboxed_stdio_launch",
        reason="STDIO launch satisfies registered command, sandbox, environment, network, data, and approval boundary",
        runtime_request=runtime_request,
        matched_launch=launch,
        matched_profile=profile,
    )


def parse_key_value(values: list[str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for value in values:
        key, separator, item = value.partition("=")
        if not separator:
            raise StdioLaunchDecisionError(f"expected KEY=VALUE, got {value!r}")
        output[key.strip()] = item.strip()
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launch-pack", type=Path, default=DEFAULT_STDIO_LAUNCH_PACK)
    parser.add_argument("--launch-id", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--arg", action="append", default=[])
    parser.add_argument("--agent-id", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--client-id", default=None)
    parser.add_argument("--correlation-id", default=None)
    parser.add_argument("--package-name", default=None)
    parser.add_argument("--package-version", default=None)
    parser.add_argument("--package-hash", default=None)
    parser.add_argument("--package-install-on-launch", action="store_true")
    parser.add_argument("--signature-present", action="store_true")
    parser.add_argument("--publisher-verified", action="store_true")
    parser.add_argument("--sandboxed", action="store_true")
    parser.add_argument("--network-egress", default="allowlist")
    parser.add_argument("--allowed-external-host", action="append", default=[])
    parser.add_argument("--allows-private-network", action="store_true")
    parser.add_argument("--filesystem-root", action="append", default=[])
    parser.add_argument("--env-key", action="append", default=[])
    parser.add_argument("--contains-secret", action="store_true")
    parser.add_argument("--env-contains-secret", action="store_true")
    parser.add_argument("--data-class", action="append", default=[])
    parser.add_argument("--requested-capability", action="append", default=[])
    parser.add_argument("--run-as-root", action="store_true")
    parser.add_argument("--requests-privilege-escalation", action="store_true")
    parser.add_argument("--approval", action="append", default=[], help="Approval field as KEY=VALUE.")
    parser.add_argument("--runtime-kill-signal", default=None)
    parser.add_argument("--expect-decision", default=None)
    parser.add_argument("--json", action="store_true", help="Print full JSON decision.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pack = load_json(args.launch_pack)
        request = {
            "agent_id": args.agent_id,
            "allowed_external_hosts": args.allowed_external_host,
            "allows_private_network": args.allows_private_network,
            "args": args.arg,
            "client_id": args.client_id,
            "command": args.command,
            "contains_secret": args.contains_secret,
            "correlation_id": args.correlation_id,
            "data_classes": args.data_class,
            "env_contains_secret": args.env_contains_secret,
            "env_keys": args.env_key,
            "filesystem_roots": args.filesystem_root,
            "human_approval_record": parse_key_value(args.approval),
            "launch_id": args.launch_id,
            "network_egress": args.network_egress,
            "package_hash": args.package_hash,
            "package_install_on_launch": args.package_install_on_launch,
            "package_name": args.package_name,
            "package_version": args.package_version,
            "publisher_verified": args.publisher_verified,
            "requested_capabilities": args.requested_capability,
            "requests_privilege_escalation": args.requests_privilege_escalation,
            "run_as_root": args.run_as_root,
            "run_id": args.run_id,
            "runtime_kill_signal": args.runtime_kill_signal,
            "sandboxed": args.sandboxed,
            "signature_present": args.signature_present,
        }
        decision = evaluate_mcp_stdio_launch_decision(pack, request)
    except StdioLaunchDecisionError as exc:
        print(f"MCP STDIO launch decision error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(decision, indent=2, sort_keys=True))
    else:
        print(decision["decision"])
        for violation in decision.get("violations", []):
            print(f"- {violation}")

    if args.expect_decision:
        if decision["decision"] != args.expect_decision:
            print(
                f"expected decision {args.expect_decision!r}, got {decision['decision']!r}",
                file=sys.stderr,
            )
            return 1
        return 0
    return 0 if decision["decision"] in ALLOW_DECISIONS or decision["decision"].startswith("hold_") else 2


if __name__ == "__main__":
    raise SystemExit(main())
