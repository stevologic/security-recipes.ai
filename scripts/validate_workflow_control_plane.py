#!/usr/bin/env python3
"""Validate SecurityRecipes workflow-control-plane manifests.

This intentionally avoids third-party dependencies so CI can run it in a
fresh checkout before any Python environment is prepared.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


REQUIRED_GATE_PHASES = {
    "admission",
    "tool_call",
    "output",
    "pre_merge",
    "post_merge",
    "runtime",
}

VALID_STATUSES = {"pilot", "active", "paused", "retired"}
VALID_MATURITY = {"crawl", "walk", "run"}
VALID_AGENTS = {"claude", "codex", "cursor", "devin", "github_copilot"}
VALID_MCP_ACCESS = {"read", "write_branch", "write_ticket", "approval_required"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")


class ValidationError(RuntimeError):
    """Raised when a manifest has invalid shape."""


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{path} is not valid JSON: {exc}") from exc


def require(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def require_nonempty_list(value: Any, failures: list[str], label: str) -> list[Any]:
    require(isinstance(value, list) and bool(value), failures, f"{label} must be a non-empty list")
    return value if isinstance(value, list) else []


def validate_root(manifest: dict[str, Any], schema: dict[str, Any], repo_root: Path) -> list[str]:
    failures: list[str] = []

    require(manifest.get("schema_version") == "1.0", failures, "schema_version must be 1.0")
    require(manifest.get("last_reviewed"), failures, "last_reviewed is required")
    require(len(str(manifest.get("intent", ""))) >= 40, failures, "intent must describe the product goal")

    schema_id = schema.get("$id")
    require(bool(schema_id), failures, "schema must declare $id")

    phases = set(require_nonempty_list(manifest.get("required_gate_phases"), failures, "required_gate_phases"))
    require(
        REQUIRED_GATE_PHASES.issubset(phases),
        failures,
        f"required_gate_phases must include {sorted(REQUIRED_GATE_PHASES)}",
    )

    standards = require_nonempty_list(manifest.get("standards_alignment"), failures, "standards_alignment")
    require(len(standards) >= 4, failures, "standards_alignment must include at least four primary references")
    seen_standards: set[str] = set()
    for idx, standard in enumerate(standards):
        label = f"standards_alignment[{idx}]"
        require(isinstance(standard, dict), failures, f"{label} must be an object")
        if not isinstance(standard, dict):
            continue
        standard_id = str(standard.get("id", "")).strip()
        require(bool(standard_id), failures, f"{label}.id is required")
        require(standard_id not in seen_standards, failures, f"{label}.id duplicates {standard_id}")
        seen_standards.add(standard_id)
        require(str(standard.get("url", "")).startswith("https://"), failures, f"{label}.url must be https")
        require(bool(standard.get("why_it_matters")), failures, f"{label}.why_it_matters is required")

    workflows = require_nonempty_list(manifest.get("workflows"), failures, "workflows")
    seen_workflows: set[str] = set()
    for idx, workflow in enumerate(workflows):
        validate_workflow(workflow, idx, repo_root, phases, seen_workflows, failures)

    return failures


def validate_workflow(
    workflow: Any,
    index: int,
    repo_root: Path,
    required_phases: set[str],
    seen_workflows: set[str],
    failures: list[str],
) -> None:
    label = f"workflows[{index}]"
    require(isinstance(workflow, dict), failures, f"{label} must be an object")
    if not isinstance(workflow, dict):
        return

    workflow_id = str(workflow.get("id", "")).strip()
    prefix = f"workflow {workflow_id or index}"
    require(bool(ID_RE.match(workflow_id)), failures, f"{prefix}: id must be kebab-case")
    require(workflow_id not in seen_workflows, failures, f"{prefix}: duplicate workflow id")
    seen_workflows.add(workflow_id)

    require(str(workflow.get("title", "")).strip(), failures, f"{prefix}: title is required")
    require(workflow.get("status") in VALID_STATUSES, failures, f"{prefix}: status is invalid")
    require(workflow.get("maturity_stage") in VALID_MATURITY, failures, f"{prefix}: maturity_stage is invalid")

    content_path = str(workflow.get("content_path", "")).strip()
    require(bool(content_path), failures, f"{prefix}: content_path is required")
    if content_path:
        require((repo_root / content_path).exists(), failures, f"{prefix}: content_path does not exist: {content_path}")

    public_path = str(workflow.get("public_path", "")).strip()
    require(public_path.startswith("/") and public_path.endswith("/"), failures, f"{prefix}: public_path must be absolute")

    owner = workflow.get("owner")
    require(isinstance(owner, dict), failures, f"{prefix}: owner must be an object")
    if isinstance(owner, dict):
        require(str(owner.get("accountable_team", "")).strip(), failures, f"{prefix}: accountable_team is required")
        require_nonempty_list(owner.get("reviewer_pools"), failures, f"{prefix}: reviewer_pools")

    require_nonempty_list(workflow.get("eligible_findings"), failures, f"{prefix}: eligible_findings")

    agents = set(require_nonempty_list(workflow.get("default_agents"), failures, f"{prefix}: default_agents"))
    unknown_agents = sorted(agents - VALID_AGENTS)
    require(not unknown_agents, failures, f"{prefix}: unknown default_agents: {unknown_agents}")

    automation_first = workflow.get("automation_first")
    require(isinstance(automation_first, list), failures, f"{prefix}: automation_first must be a list")

    validate_mcp_context(workflow.get("mcp_context"), prefix, failures)
    validate_scope(workflow.get("scope"), prefix, failures)
    validate_gates(workflow.get("gates"), prefix, required_phases, failures)
    validate_evidence(workflow.get("evidence"), prefix, failures)
    validate_kpis(workflow.get("kpis"), prefix, failures)
    require_nonempty_list(workflow.get("kill_signals"), failures, f"{prefix}: kill_signals")


def validate_mcp_context(value: Any, prefix: str, failures: list[str]) -> None:
    contexts = require_nonempty_list(value, failures, f"{prefix}: mcp_context")
    seen_namespaces: set[str] = set()
    for idx, context in enumerate(contexts):
        label = f"{prefix}: mcp_context[{idx}]"
        require(isinstance(context, dict), failures, f"{label} must be an object")
        if not isinstance(context, dict):
            continue
        namespace = str(context.get("namespace", "")).strip()
        require(bool(namespace), failures, f"{label}.namespace is required")
        require("*" not in namespace, failures, f"{label}.namespace must not use wildcards")
        require(namespace not in seen_namespaces, failures, f"{label}.namespace duplicates {namespace}")
        seen_namespaces.add(namespace)
        require(context.get("access") in VALID_MCP_ACCESS, failures, f"{label}.access is invalid")
        require(str(context.get("purpose", "")).strip(), failures, f"{label}.purpose is required")


def validate_scope(value: Any, prefix: str, failures: list[str]) -> None:
    require(isinstance(value, dict), failures, f"{prefix}: scope must be an object")
    if not isinstance(value, dict):
        return
    require_nonempty_list(value.get("allowed_paths"), failures, f"{prefix}: scope.allowed_paths")
    require_nonempty_list(value.get("forbidden_paths"), failures, f"{prefix}: scope.forbidden_paths")
    max_changed = value.get("max_changed_files")
    max_lines = value.get("max_diff_lines")
    require(isinstance(max_changed, int) and 1 <= max_changed <= 25, failures, f"{prefix}: max_changed_files out of range")
    require(isinstance(max_lines, int) and 1 <= max_lines <= 2000, failures, f"{prefix}: max_diff_lines out of range")


def validate_gates(value: Any, prefix: str, required_phases: set[str], failures: list[str]) -> None:
    require(isinstance(value, dict), failures, f"{prefix}: gates must be an object")
    if not isinstance(value, dict):
        return

    missing = sorted(required_phases - set(value.keys()))
    require(not missing, failures, f"{prefix}: gates missing phases: {missing}")
    for phase in sorted(required_phases):
        rules = require_nonempty_list(value.get(phase), failures, f"{prefix}: gates.{phase}")
        for idx, rule in enumerate(rules):
            require(isinstance(rule, str) and len(rule.strip()) >= 8, failures, f"{prefix}: gates.{phase}[{idx}] is too short")


def validate_evidence(value: Any, prefix: str, failures: list[str]) -> None:
    evidence = require_nonempty_list(value, failures, f"{prefix}: evidence")
    require(len(evidence) >= 3, failures, f"{prefix}: evidence must include at least three records")
    seen: set[str] = set()
    for idx, item in enumerate(evidence):
        label = f"{prefix}: evidence[{idx}]"
        require(isinstance(item, dict), failures, f"{label} must be an object")
        if not isinstance(item, dict):
            continue
        evidence_id = str(item.get("id", "")).strip()
        require(bool(ID_RE.match(evidence_id)), failures, f"{label}.id must be kebab-case")
        require(evidence_id not in seen, failures, f"{label}.id duplicates {evidence_id}")
        seen.add(evidence_id)
        require(str(item.get("source", "")).strip(), failures, f"{label}.source is required")
        require(str(item.get("retention", "")).strip(), failures, f"{label}.retention is required")
        require(str(item.get("evidence_owner", "")).strip(), failures, f"{label}.evidence_owner is required")


def validate_kpis(value: Any, prefix: str, failures: list[str]) -> None:
    kpis = require_nonempty_list(value, failures, f"{prefix}: kpis")
    require(len(kpis) >= 3, failures, f"{prefix}: kpis must include at least three targets")
    seen: set[str] = set()
    for idx, item in enumerate(kpis):
        label = f"{prefix}: kpis[{idx}]"
        require(isinstance(item, dict), failures, f"{label} must be an object")
        if not isinstance(item, dict):
            continue
        kpi_id = str(item.get("id", "")).strip()
        require(bool(kpi_id), failures, f"{label}.id is required")
        require(kpi_id not in seen, failures, f"{label}.id duplicates {kpi_id}")
        seen.add(kpi_id)
        require(str(item.get("target", "")).strip(), failures, f"{label}.target is required")


def build_report(
    manifest: dict[str, Any],
    failures: list[str],
    generated_at: str | None = None,
) -> dict[str, Any]:
    workflows = []
    for workflow in manifest.get("workflows", []):
        if not isinstance(workflow, dict):
            continue
        gates = workflow.get("gates") if isinstance(workflow.get("gates"), dict) else {}
        workflows.append(
            {
                "id": workflow.get("id"),
                "title": workflow.get("title"),
                "status": workflow.get("status"),
                "maturity_stage": workflow.get("maturity_stage"),
                "content_path": workflow.get("content_path"),
                "public_path": workflow.get("public_path"),
                "gate_phase_count": len(gates),
                "evidence_count": len(workflow.get("evidence", []) or []),
                "kpi_count": len(workflow.get("kpis", []) or []),
                "mcp_namespaces": [
                    item.get("namespace")
                    for item in workflow.get("mcp_context", [])
                    if isinstance(item, dict)
                ],
            }
        )

    return {
        "generated_at": generated_at or str(manifest.get("last_reviewed", "")),
        "schema_version": manifest.get("schema_version"),
        "last_reviewed": manifest.get("last_reviewed"),
        "workflow_count": len(workflows),
        "active_workflow_count": sum(1 for workflow in workflows if workflow.get("status") == "active"),
        "required_gate_phases": manifest.get("required_gate_phases", []),
        "standards_alignment": [
            {
                "id": item.get("id"),
                "url": item.get("url"),
            }
            for item in manifest.get("standards_alignment", [])
            if isinstance(item, dict)
        ],
        "workflows": workflows,
        "failure_count": len(failures),
        "failures": failures,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=Path("data/control-plane/workflow-manifests.json"))
    parser.add_argument("--schema", type=Path, default=Path("data/control-plane/workflow-manifest.schema.json"))
    parser.add_argument("--report", type=Path, default=Path("data/evidence/workflow-control-plane-report.json"))
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--no-write-report", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    manifest_path = args.manifest if args.manifest.is_absolute() else repo_root / args.manifest
    schema_path = args.schema if args.schema.is_absolute() else repo_root / args.schema
    report_path = args.report if args.report.is_absolute() else repo_root / args.report

    failures: list[str] = []
    try:
        manifest = load_json(manifest_path)
        schema = load_json(schema_path)
        require(isinstance(manifest, dict), failures, "manifest root must be an object")
        require(isinstance(schema, dict), failures, "schema root must be an object")
        if isinstance(manifest, dict) and isinstance(schema, dict):
            failures.extend(validate_root(manifest, schema, repo_root))
    except ValidationError as exc:
        failures.append(str(exc))
        manifest = {}

    report = build_report(
        manifest if isinstance(manifest, dict) else {},
        failures,
        generated_at=args.generated_at,
    )
    if not args.no_write_report:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if failures:
        print("workflow control-plane validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "Validated "
        f"{report['workflow_count']} workflow manifests across "
        f"{len(report['required_gate_phases'])} gate phases. "
        f"Report: {report_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
