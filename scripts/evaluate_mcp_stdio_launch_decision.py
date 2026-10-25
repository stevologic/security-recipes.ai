#!/usr/bin/env python3
"""Evaluate one MCP STDIO launch decision.

The evaluator is designed for MCP clients, endpoint policy agents, and
CI gates that need a deterministic answer before spawning a local MCP
server subprocess. MCP 2026-07-28 local-server security treats
configuration-level filesystem allowlists as cooperative guardrails,
not a security boundary. Unspecified isolation evidence stays on the
prior allow path so existing sandboxed=true checks remain valid.
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
    "hold_for_discover_probe",
    "deny_unregistered_stdio_launch",
    "deny_untrusted_package_launch",
    "deny_shell_or_network_bootstrap",
    "deny_unrestricted_proxy_spawn",
    "deny_cooperative_filesystem_boundary",
    "kill_session_on_secret_or_privilege_request",
}
COOPERATIVE_ISOLATION_KINDS = {
    "allowlist",
    "allowlist_only",
    "bare_chroot",
    "bare_process",
    "chroot",
    "config_allowlist",
    "cooperative",
    "cooperative_allowlist",
    "filesystem_allowlist",
    "filesystem_roots",
    "mcp_roots",
    "none",
    "roots",
    "unisolated",
}
DUAL_ERA_CLIENTS = {"dual_era", "legacy"}
PROXY_ARCHITECTURES = {"proxy", "stdio_proxy", "local_proxy"}
MODERN_DISCOVER_RESULTS = {"complete", "discoverresult", "discover_result"}


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


def normalized_token(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def client_era(runtime_request: dict[str, Any]) -> str:
    return normalized_token(runtime_request.get("client_era"))


def has_discover_probe(runtime_request: dict[str, Any]) -> bool:
    if runtime_request.get("stdio_discover_probe") or runtime_request.get("discover_probe_planned"):
        return True
    return str(runtime_request.get("discover_method") or "").strip() == "server/discover"


def modern_discover_outcome(runtime_request: dict[str, Any]) -> bool:
    result = normalized_token(runtime_request.get("discover_result_type"))
    if result in MODERN_DISCOVER_RESULTS:
        return True
    error = normalized_token(
        runtime_request.get("discover_error") or runtime_request.get("discover_jsonrpc_error")
    )
    return "unsupportedprotocolversion" in error.replace("_", "")


def initialize_fallback_after_modern(runtime_request: dict[str, Any]) -> bool:
    fallback = bool(
        runtime_request.get("initialize_fallback")
        or runtime_request.get("legacy_initialize_after_modern_discover")
        or runtime_request.get("legacy_initialize_without_discover")
    )
    return fallback and modern_discover_outcome(runtime_request)


def launch_architecture(runtime_request: dict[str, Any], launch: dict[str, Any] | None) -> str:
    registered = as_dict(launch).get("launch_architecture")
    return normalized_token(runtime_request.get("launch_architecture") or registered or "direct")


def isolation_kind(runtime_request: dict[str, Any]) -> str:
    return normalized_token(
        runtime_request.get("isolation_kind")
        or runtime_request.get("sandbox_kind")
        or runtime_request.get("filesystem_enforcement")
    )


def cooperative_filesystem_boundary_violations(runtime_request: dict[str, Any]) -> list[str]:
    """Return violations when isolation evidence is only a cooperative allowlist.

    Unspecified isolation_kind stays on the prior sandboxed=true path.
    """
    kind = isolation_kind(runtime_request)
    if not kind or kind not in COOPERATIVE_ISOLATION_KINDS:
        return []
    if kind in {"chroot", "bare_chroot"}:
        return ["bare chroot is not a process sandbox"]
    if kind in {"mcp_roots", "roots", "filesystem_roots"}:
        return ["MCP Roots and declared filesystem roots are cooperative, not access control"]
    if kind in {"bare_process", "none", "unisolated"}:
        return ["stdio process is not isolated by a container, VM, or OS process sandbox"]
    return ["filesystem allowlist is a cooperative boundary, not OS isolation"]


def proxy_spawn_violations(runtime_request: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    extra_auth = bool(runtime_request.get("proxy_spawn_authorized")) or has_approval(
        runtime_request.get("human_approval_record")
    )
    logged = bool(
        runtime_request.get("stdio_spawn_logged") or runtime_request.get("proxy_stdio_logged")
    )
    if not extra_auth:
        violations.append("proxy spawn lacks additional authorization")
    if not runtime_request.get("sandboxed"):
        violations.append("proxy-spawned stdio process is not sandboxed")
    if not logged:
        violations.append("proxy stdio spawn is not logged")
    return violations


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
            "client_era": runtime_request.get("client_era"),
            "command": runtime_request.get("command"),
            "correlation_id": runtime_request.get("correlation_id"),
            "discover_method": runtime_request.get("discover_method"),
            "discover_result_type": runtime_request.get("discover_result_type"),
            "env_keys": as_list(runtime_request.get("env_keys")),
            "initialize_fallback": runtime_request.get("initialize_fallback"),
            "isolation_kind": runtime_request.get("isolation_kind")
            or runtime_request.get("sandbox_kind")
            or runtime_request.get("filesystem_enforcement"),
            "launch_architecture": runtime_request.get("launch_architecture"),
            "launch_id": runtime_request.get("launch_id"),
            "network_egress": runtime_request.get("network_egress"),
            "package_hash": runtime_request.get("package_hash"),
            "package_install_on_launch": runtime_request.get("package_install_on_launch"),
            "package_name": runtime_request.get("package_name"),
            "package_version": runtime_request.get("package_version"),
            "proxy_spawn_authorized": runtime_request.get("proxy_spawn_authorized"),
            "requested_capabilities": as_list(runtime_request.get("requested_capabilities")),
            "run_id": runtime_request.get("run_id"),
            "sandboxed": runtime_request.get("sandboxed"),
            "stdio_discover_probe": runtime_request.get("stdio_discover_probe"),
            "stdio_spawn_logged": runtime_request.get("stdio_spawn_logged"),
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

    architecture = launch_architecture(runtime_request, launch)
    if architecture in PROXY_ARCHITECTURES:
        proxy_violations = proxy_spawn_violations(runtime_request)
        if proxy_violations:
            return decision_result(
                decision="deny_unrestricted_proxy_spawn",
                reason="MCP proxy services that spawn STDIO children need extra authorization, sandbox or container isolation, and stdio usage logging so a stolen proxy token cannot become host RCE",
                runtime_request=runtime_request,
                matched_launch=launch,
                matched_profile=profile,
                violations=proxy_violations,
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

    cooperative_violations = cooperative_filesystem_boundary_violations(runtime_request)
    if cooperative_violations:
        return decision_result(
            decision="deny_cooperative_filesystem_boundary",
            reason="MCP local-server security treats configuration-level filesystem allowlists, MCP Roots, and bare chroot as cooperative guardrails, not a security boundary; enforcement requires a container, VM, or OS process sandbox",
            runtime_request=runtime_request,
            matched_launch=launch,
            matched_profile=profile,
            violations=cooperative_violations,
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

    if client_era(runtime_request) in DUAL_ERA_CLIENTS:
        if initialize_fallback_after_modern(runtime_request):
            return decision_result(
                decision="hold_for_discover_probe",
                reason="MCP 2026-07-28 forbids falling back to initialize after a DiscoverResult or UnsupportedProtocolVersionError; the server is modern and era-ambiguous methods must not run under legacy semantics",
                runtime_request=runtime_request,
                matched_launch=launch,
                matched_profile=profile,
                violations=["initialize fallback after modern server/discover outcome"],
            )
        if not has_discover_probe(runtime_request):
            return decision_result(
                decision="hold_for_discover_probe",
                reason="Dual-era STDIO clients SHOULD probe with server/discover before any other request because stdio has no HTTP status code to drive fallback",
                runtime_request=runtime_request,
                matched_launch=launch,
                matched_profile=profile,
                violations=["dual-era stdio client skipped server/discover probe"],
            )

    return decision_result(
        decision="allow_pinned_sandboxed_stdio_launch",
        reason="STDIO launch satisfies registered command, sandbox, environment, network, data, discover-probe, and approval boundary",
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
    parser.add_argument("--isolation-kind", default=None)
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
    parser.add_argument("--client-era", default=None)
    parser.add_argument("--discover-method", default=None)
    parser.add_argument("--stdio-discover-probe", action="store_true")
    parser.add_argument("--discover-result-type", default=None)
    parser.add_argument("--discover-error", default=None)
    parser.add_argument("--initialize-fallback", action="store_true")
    parser.add_argument("--launch-architecture", default=None)
    parser.add_argument("--proxy-spawn-authorized", action="store_true")
    parser.add_argument("--stdio-spawn-logged", action="store_true")
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
            "client_era": args.client_era,
            "client_id": args.client_id,
            "command": args.command,
            "discover_error": args.discover_error,
            "discover_method": args.discover_method,
            "discover_result_type": args.discover_result_type,
            "contains_secret": args.contains_secret,
            "correlation_id": args.correlation_id,
            "data_classes": args.data_class,
            "env_contains_secret": args.env_contains_secret,
            "env_keys": args.env_key,
            "filesystem_roots": args.filesystem_root,
            "human_approval_record": parse_key_value(args.approval),
            "initialize_fallback": args.initialize_fallback,
            "isolation_kind": args.isolation_kind,
            "launch_architecture": args.launch_architecture,
            "launch_id": args.launch_id,
            "network_egress": args.network_egress,
            "package_hash": args.package_hash,
            "package_install_on_launch": args.package_install_on_launch,
            "package_name": args.package_name,
            "package_version": args.package_version,
            "proxy_spawn_authorized": args.proxy_spawn_authorized,
            "publisher_verified": args.publisher_verified,
            "requested_capabilities": args.requested_capability,
            "requests_privilege_escalation": args.requests_privilege_escalation,
            "run_as_root": args.run_as_root,
            "run_id": args.run_id,
            "runtime_kill_signal": args.runtime_kill_signal,
            "sandboxed": args.sandboxed,
            "signature_present": args.signature_present,
            "stdio_discover_probe": args.stdio_discover_probe,
            "stdio_spawn_logged": args.stdio_spawn_logged,
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
