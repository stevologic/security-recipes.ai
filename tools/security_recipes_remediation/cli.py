"""Command line interface for the security-recipes.ai remediation suite."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .playbooks import (
    ALLOWED_EVIDENCE_KINDS,
    DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_TOTAL_BYTES,
    inspect_workspace,
    load_playbook_registry,
    playbook_by_id,
    record_evidence,
    start_run,
    verify_run,
)
from .suite import (
    build_remediation_packet,
    domain_by_key,
    load_domain_registry,
    load_finding,
    load_llm_config,
    score_domains,
    write_packet,
)
from .webapp import DEFAULT_STATE_DIR, run_dashboard


def main(argv: list[str] | None = None) -> int:
    registry = load_domain_registry()
    parser = build_parser(registry)
    args = parser.parse_args(argv)
    try:
        return int(args.func(args, registry))
    except BrokenPipeError:
        return 1
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def build_parser(registry: dict[str, Any]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-recipes-remediation-suite",
        description="Plan bounded, recipe-guided security remediation work for enterprise agent workflows.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list-domains", help="List every remediation domain and custom tool command.")
    list_parser.set_defaults(func=cmd_list_domains)

    describe_parser = subparsers.add_parser("describe", help="Describe one remediation domain.")
    describe_parser.add_argument("--domain", "--tool", required=True, help="Domain id or custom tool command.")
    describe_parser.set_defaults(func=cmd_describe)

    serve_parser = subparsers.add_parser(
        "serve-dashboard",
        help="Run a local browser dashboard for configuring and triggering remediation-suite plans.",
    )
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind host. Use 0.0.0.0 inside containers.")
    serve_parser.add_argument("--port", type=int, default=8787, help="Dashboard port.")
    serve_parser.add_argument(
        "--state-dir",
        default=str(DEFAULT_STATE_DIR),
        help="Directory for persisted non-secret dashboard configuration.",
    )
    serve_parser.set_defaults(func=cmd_serve_dashboard)

    plan_parser = subparsers.add_parser("plan", help="Build a remediation packet for an explicit domain.")
    add_plan_arguments(plan_parser, require_domain=True)
    plan_parser.set_defaults(func=cmd_plan)

    playbook_parser = subparsers.add_parser(
        "playbook",
        help="Inspect workspaces and manage evidence-backed playbook runs.",
    )
    add_playbook_parsers(playbook_parser)

    for domain in registry["domains"]:
        command = str(domain["command"])
        domain_parser = subparsers.add_parser(
            command,
            help=f"{domain['title']} tool ({domain['id']}).",
            description=str(domain.get("purpose", "")),
        )
        add_plan_arguments(domain_parser, require_domain=False)
        domain_parser.set_defaults(func=cmd_plan, fixed_domain=domain["id"])

    return parser


def add_playbook_parsers(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(dest="playbook_command", required=True)

    list_parser = subparsers.add_parser("list", help="List executable remediation playbooks.")
    list_parser.add_argument("--category", default=None, help="Only include playbooks from this category.")
    list_parser.set_defaults(func=cmd_playbook_list)

    describe_parser = subparsers.add_parser("describe", help="Describe one executable playbook profile.")
    describe_parser.add_argument("--playbook", required=True, help="Playbook id.")
    describe_parser.set_defaults(func=cmd_playbook_describe)

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Create a bounded, hash-only inventory of files selected by a playbook.",
    )
    inspect_parser.add_argument("--playbook", required=True, help="Playbook id.")
    inspect_parser.add_argument("--workspace", required=True, help="Existing workspace directory.")
    add_inspection_limit_arguments(inspect_parser)
    inspect_parser.set_defaults(func=cmd_playbook_inspect)

    start_parser = subparsers.add_parser("start", help="Create an evidence-backed playbook run packet.")
    start_parser.add_argument("--playbook", required=True, help="Playbook id.")
    start_parser.add_argument("--workspace", required=True, help="Existing workspace directory.")
    start_parser.add_argument(
        "--finding",
        required=True,
        help="Finding metadata file inside the workspace. Contents are hashed, not copied.",
    )
    start_parser.add_argument("--run-dir", required=True, help="New run directory inside the workspace.")
    add_inspection_limit_arguments(start_parser)
    start_parser.set_defaults(func=cmd_playbook_start)

    record_parser = subparsers.add_parser("record", help="Record metadata and a hash for an evidence file.")
    record_parser.add_argument("--run-dir", required=True, help="Existing playbook run directory.")
    record_parser.add_argument("--file", required=True, help="Evidence file inside the run workspace.")
    record_parser.add_argument(
        "--kind",
        required=True,
        choices=sorted(ALLOWED_EVIDENCE_KINDS),
        help="Evidence type.",
    )
    record_parser.add_argument(
        "--requirement",
        action="append",
        default=[],
        help="Exact evidence requirement satisfied by this file. Repeat for multiple requirements.",
    )
    record_parser.add_argument("--label", default=None, help="Optional human-readable evidence label.")
    record_parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help="Maximum evidence file size accepted for hashing.",
    )
    record_parser.set_defaults(func=cmd_playbook_record)

    verify_parser = subparsers.add_parser("verify", help="Verify run schemas, profile identity, and evidence hashes.")
    verify_parser.add_argument("--run-dir", required=True, help="Existing playbook run directory.")
    verify_parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help="Maximum finding or evidence file size accepted while verifying.",
    )
    verify_parser.set_defaults(func=cmd_playbook_verify)


def add_inspection_limit_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help="Maximum matched files to hash.")
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help="Maximum size of one file selected for hashing.",
    )
    parser.add_argument(
        "--max-total-bytes",
        type=int,
        default=DEFAULT_MAX_TOTAL_BYTES,
        help="Maximum aggregate bytes selected for hashing.",
    )
    parser.add_argument(
        "--max-entries",
        type=int,
        default=DEFAULT_MAX_ENTRIES,
        help="Maximum workspace file entries visited.",
    )


def add_plan_arguments(parser: argparse.ArgumentParser, *, require_domain: bool) -> None:
    if require_domain:
        parser.add_argument("--domain", "--tool", required=True, help="Domain id or custom tool command.")
    parser.add_argument(
        "--finding",
        default="-",
        help="Finding payload path. Use '-' for stdin. Supports free text, generic JSON, and SARIF JSON.",
    )
    parser.add_argument(
        "--recipes-source",
        default=None,
        help="Recipe JSON source. Defaults to public/api/recipes.json when present, otherwise the site endpoint.",
    )
    parser.add_argument(
        "--tooling",
        default="",
        help="Comma-separated enterprise tools to highlight, for example 'github,snyk,jira'.",
    )
    parser.add_argument("--ecosystem", default=None, help="Optional ecosystem hint such as npm, python, go, container, solidity.")
    parser.add_argument("--llm-config", default=None, help="Optional JSON config for an OpenAI-compatible chat completions endpoint.")
    parser.add_argument(
        "--llm-mode",
        choices=["off", "prompt", "call"],
        default="off",
        help="off returns no LLM payload, prompt returns the prompt, call invokes the configured endpoint.",
    )
    parser.add_argument("--max-recipes", type=int, default=6, help="Maximum imported recipes to attach.")
    parser.add_argument("--output", "-o", default="-", help="Output JSON path. Defaults to stdout.")


def cmd_list_domains(args: argparse.Namespace, registry: dict[str, Any]) -> int:
    rows = [
        {
            "id": domain["id"],
            "command": domain["command"],
            "title": domain["title"],
            "page": domain.get("page"),
        }
        for domain in registry["domains"]
    ]
    print(json.dumps({"suite": registry.get("suite", {}), "domains": rows}, indent=2, sort_keys=True))
    return 0


def cmd_describe(args: argparse.Namespace, registry: dict[str, Any]) -> int:
    domain = domain_by_key(registry, args.domain)
    print(json.dumps(domain, indent=2, sort_keys=True))
    return 0


def cmd_plan(args: argparse.Namespace, registry: dict[str, Any]) -> int:
    domain_key = getattr(args, "fixed_domain", None) or args.domain
    findings = load_finding(args.finding)
    if not getattr(args, "fixed_domain", None) and str(domain_key).lower() == "auto":
        scored = score_domains(registry, findings[0])
        if not scored or scored[0]["score"] <= 0:
            raise ValueError("auto domain selection could not find a matching domain")
        domain_key = str(scored[0]["id"])
    packet = build_remediation_packet(
        domain_key=domain_key,
        findings=findings,
        registry=registry,
        recipe_source=args.recipes_source,
        tooling=_csv(args.tooling),
        ecosystem=args.ecosystem,
        llm_config=load_llm_config(args.llm_config),
        llm_mode=args.llm_mode,
        max_recipes=max(1, args.max_recipes),
    )
    write_packet(packet, Path(args.output) if args.output else None)
    return 0


def cmd_serve_dashboard(args: argparse.Namespace, registry: dict[str, Any]) -> int:
    del registry
    run_dashboard(host=str(args.host), port=int(args.port), state_dir=args.state_dir)
    return 0


def cmd_playbook_list(args: argparse.Namespace, domain_registry: dict[str, Any]) -> int:
    del domain_registry
    registry = load_playbook_registry()
    playbooks = registry["playbooks"]
    if args.category:
        wanted = str(args.category).strip().lower()
        playbooks = [item for item in playbooks if str(item["category"]).lower() == wanted]
    rows = [
        {
            "id": item["id"],
            "title": item["title"],
            "category": item["category"],
            "page": item["page"],
            "summary": item["summary"],
        }
        for item in playbooks
    ]
    _print_json(
        {
            "schema_version": registry["schema_version"],
            "suite_version": registry["suite_version"],
            "count": len(rows),
            "playbooks": rows,
        }
    )
    return 0


def cmd_playbook_describe(args: argparse.Namespace, domain_registry: dict[str, Any]) -> int:
    del domain_registry
    registry = load_playbook_registry()
    _print_json(playbook_by_id(registry, args.playbook))
    return 0


def cmd_playbook_inspect(args: argparse.Namespace, domain_registry: dict[str, Any]) -> int:
    del domain_registry
    registry = load_playbook_registry()
    playbook = playbook_by_id(registry, args.playbook)
    _print_json(
        inspect_workspace(
            playbook=playbook,
            workspace=args.workspace,
            max_files=args.max_files,
            max_file_bytes=args.max_file_bytes,
            max_total_bytes=args.max_total_bytes,
            max_entries=args.max_entries,
        )
    )
    return 0


def cmd_playbook_start(args: argparse.Namespace, domain_registry: dict[str, Any]) -> int:
    del domain_registry
    registry = load_playbook_registry()
    _print_json(
        start_run(
            registry=registry,
            playbook_id=args.playbook,
            workspace=args.workspace,
            finding=args.finding,
            run_dir=args.run_dir,
            max_files=args.max_files,
            max_file_bytes=args.max_file_bytes,
            max_total_bytes=args.max_total_bytes,
            max_entries=args.max_entries,
        )
    )
    return 0


def cmd_playbook_record(args: argparse.Namespace, domain_registry: dict[str, Any]) -> int:
    del domain_registry
    _print_json(
        record_evidence(
            run_dir=args.run_dir,
            evidence_file=args.file,
            kind=args.kind,
            requirements=args.requirement,
            label=args.label,
            max_file_bytes=args.max_file_bytes,
        )
    )
    return 0


def cmd_playbook_verify(args: argparse.Namespace, domain_registry: dict[str, Any]) -> int:
    del domain_registry
    result = verify_run(
        run_dir=args.run_dir,
        registry=load_playbook_registry(),
        max_file_bytes=args.max_file_bytes,
    )
    _print_json(result)
    if not result["valid"]:
        return 2
    if not result["complete"]:
        return 3
    return 0


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


if __name__ == "__main__":
    raise SystemExit(main())
