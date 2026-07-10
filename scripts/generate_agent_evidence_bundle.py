#!/usr/bin/env python3
"""Generate an audit evidence bundle for agentic remediation runs.

Input can be a JSON array or JSON Lines file. Each event must include:

  run_id, event_class (or legacy event_type), and a timestamp

Use workflow_id for the workflow identifier; legacy workflow is accepted.
When timestamp is absent, canonical receipt time fields such as approved_at,
completed_at, closed_at, or revoked_at are normalized into it.

Additional keys are preserved in the raw event stream. The output bundle is
intentionally boring JSON + Markdown so compliance, GRC, and security teams can
archive it without adopting a proprietary database first.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REQUIRED_FIELDS = {"run_id"}
TIMESTAMP_FIELDS = (
    "timestamp",
    "occurred_at",
    "event_time",
    "issued_at",
    "retrieved_at",
    "scanned_at",
    "decided_at",
    "approved_at",
    "completed_at",
    "attached_at",
    "closed_at",
    "revoked_at",
)
TERMINAL_EVENTS = {
    "run_closed",
    "pr_opened",
    "triage_written",
    "agent_stopped",
    "run_failed",
    "finding_closed",
}
REVIEW_EVENTS = {"human_approval", "review_approved", "review_rejected", "changes_requested"}
VERIFY_EVENTS = {"verifier_result", "tests_passed", "scanner_rerun_passed", "policy_checks_passed"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an audit-ready evidence bundle from agent run events."
    )
    parser.add_argument("--events", required=True, help="Path to JSON or JSONL event file.")
    parser.add_argument("--output-dir", required=True, help="Directory for generated bundle files.")
    parser.add_argument(
        "--program",
        default="agentic-security-remediation",
        help="Program name written into the bundle manifest.",
    )
    parser.add_argument(
        "--period",
        default="unspecified",
        help="Audit period label, e.g. 2026-Q2 or 2026-05.",
    )
    return parser.parse_args()


def load_events(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        raise ValueError(f"{path} is empty")

    if raw[0] == "[":
        payload = json.loads(raw)
        if not isinstance(payload, list):
            raise ValueError("top-level JSON payload must be an array")
        events = payload
    else:
        events = [json.loads(line) for line in raw.splitlines() if line.strip()]

    shaped: list[dict[str, Any]] = []
    for idx, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ValueError(f"event {idx} is not a JSON object")
        missing = sorted(REQUIRED_FIELDS - event.keys())
        if missing:
            raise ValueError(f"event {idx} missing required fields: {missing}")
        event = dict(event)
        normalize_alias(event, "event_class", "event_type", idx, required=True)
        normalize_alias(event, "workflow_id", "workflow", idx, required=False)
        event["timestamp"] = normalize_timestamp(event_timestamp(event, idx))
        for field in TIMESTAMP_FIELDS:
            if field != "timestamp" and str(event.get(field, "")).strip():
                event[field] = normalize_timestamp(str(event[field]))
        shaped.append(event)

    shaped.sort(key=lambda e: (e["timestamp"], str(e.get("run_id", "")), event_name(e)))
    return shaped


def normalize_alias(
    event: dict[str, Any], canonical: str, legacy: str, index: int, *, required: bool
) -> None:
    canonical_value = str(event.get(canonical, "")).strip()
    legacy_value = str(event.get(legacy, "")).strip()
    if canonical_value and legacy_value and canonical_value != legacy_value:
        raise ValueError(f"event {index} has conflicting {canonical} and {legacy} values")
    value = canonical_value or legacy_value
    if required and not value:
        raise ValueError(f"event {index} missing {canonical} (or legacy {legacy})")
    if value:
        event[canonical] = value


def event_timestamp(event: dict[str, Any], index: int) -> str:
    for field in TIMESTAMP_FIELDS:
        value = str(event.get(field, "")).strip()
        if value:
            return value
    expected = ", ".join(TIMESTAMP_FIELDS)
    raise ValueError(f"event {index} missing a timestamp; expected one of: {expected}")


def event_name(event: dict[str, Any]) -> str:
    return str(event.get("event_class") or event.get("event_type") or "")


def event_workflow(event: dict[str, Any]) -> str:
    return str(event.get("workflow_id") or event.get("workflow") or "unknown")


def normalize_timestamp(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_json(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def group_runs(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    runs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        runs[str(event["run_id"])].append(event)
    return dict(runs)


def summarize_run(run_id: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    event_classes = [event_name(event) for event in events]
    first = events[0]
    last = events[-1]
    reviewers = sorted(
        {
            str(e.get("approver") or e.get("actor"))
            for e in events
            if event_name(e) in REVIEW_EVENTS and (e.get("approver") or e.get("actor"))
        }
    )
    tools = sorted({str(e.get("tool_namespace") or e.get("tool")) for e in events if e.get("tool_namespace") or e.get("tool")})
    repositories = sorted({str(e.get("repository")) for e in events if e.get("repository")})
    prs = sorted({str(e.get("pr_url")) for e in events if e.get("pr_url")})
    findings = sorted({str(e.get("finding_id")) for e in events if e.get("finding_id")})

    return {
        "run_id": run_id,
        "workflow_id": event_workflow(first),
        "workflow": event_workflow(first),
        "finding_ids": findings,
        "repositories": repositories,
        "started_at": first.get("timestamp"),
        "ended_at": last.get("timestamp"),
        "event_count": len(events),
        "outcome": infer_outcome(events),
        "has_terminal_event": any(name in TERMINAL_EVENTS for name in event_classes),
        "has_review_decision": any(name in REVIEW_EVENTS for name in event_classes),
        "has_verification": any(name in VERIFY_EVENTS for name in event_classes),
        "reviewers": reviewers,
        "tools": tools,
        "pull_requests": prs,
        "event_classes": sorted(set(event_classes)),
        "event_types": sorted(set(event_classes)),
        "chain_hash": sha256_json(events),
    }


def infer_outcome(events: list[dict[str, Any]]) -> str:
    for event in reversed(events):
        if event_name(event) == "run_closed":
            return str(event.get("final_state") or "run_closed")
    event_types = [event_name(event) for event in events]
    for candidate in ["finding_closed", "review_approved", "pr_opened", "triage_written", "agent_stopped", "run_failed"]:
        if candidate in event_types:
            return candidate
    return event_types[-1] if event_types else "unknown"


def build_manifest(program: str, period: str, source: Path, events: list[dict[str, Any]]) -> dict[str, Any]:
    runs = group_runs(events)
    summaries = [summarize_run(run_id, run_events) for run_id, run_events in sorted(runs.items())]
    event_counts = Counter(event_name(event) for event in events)
    workflows = Counter(event_workflow(event) for event in events)
    control_gaps = []

    for summary in summaries:
        if not summary["has_terminal_event"]:
            control_gaps.append({"run_id": summary["run_id"], "gap": "missing_terminal_event"})
        if summary["has_terminal_event"] and not summary["has_review_decision"]:
            control_gaps.append({"run_id": summary["run_id"], "gap": "missing_review_decision"})
        if summary["has_terminal_event"] and not summary["has_verification"]:
            control_gaps.append({"run_id": summary["run_id"], "gap": "missing_verification_event"})

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema": "security-recipes.agent-evidence-bundle.v2",
        "generated_at": now,
        "program": program,
        "period": period,
        "source_file": str(source),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "event_count": len(events),
        "run_count": len(summaries),
        "workflows": dict(sorted(workflows.items())),
        "event_classes": dict(sorted(event_counts.items())),
        "event_types": dict(sorted(event_counts.items())),
        "control_gaps": control_gaps,
        "runs": summaries,
        "events_sha256": sha256_json(events),
    }


def write_markdown_report(manifest: dict[str, Any], output_path: Path) -> None:
    lines = [
        "# Agentic Remediation Evidence Bundle",
        "",
        f"- Program: `{manifest['program']}`",
        f"- Period: `{manifest['period']}`",
        f"- Generated: `{manifest['generated_at']}`",
        f"- Runs: `{manifest['run_count']}`",
        f"- Events: `{manifest['event_count']}`",
        f"- Source SHA-256: `{manifest['source_sha256']}`",
        f"- Canonical events SHA-256: `{manifest['events_sha256']}`",
        "",
        "## Control Gaps",
        "",
    ]
    if manifest["control_gaps"]:
        for gap in manifest["control_gaps"]:
            lines.append(f"- `{gap['run_id']}`: {gap['gap']}")
    else:
        lines.append("- None detected by the bundle generator.")

    lines.extend(["", "## Run Summary", ""])
    for run in manifest["runs"]:
        findings = ", ".join(run["finding_ids"]) or "none"
        prs = ", ".join(run["pull_requests"]) or "none"
        lines.extend(
            [
                f"### `{run['run_id']}`",
                "",
                f"- Workflow: `{run.get('workflow_id') or 'unknown'}`",
                f"- Outcome: `{run['outcome']}`",
                f"- Finding IDs: {findings}",
                f"- Pull requests: {prs}",
                f"- Verification event present: `{str(run['has_verification']).lower()}`",
                f"- Review decision present: `{str(run['has_review_decision']).lower()}`",
                f"- Chain hash: `{run['chain_hash']}`",
                "",
            ]
        )

    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    args = parse_args()
    source = Path(args.events).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    events = load_events(source)
    manifest = build_manifest(args.program, args.period, source, events)

    (output_dir / "events.normalized.json").write_text(
        json.dumps(events, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    write_markdown_report(manifest, output_dir / "evidence-report.md")

    print(json.dumps({"output_dir": str(output_dir), "run_count": manifest["run_count"]}, indent=2))


if __name__ == "__main__":
    main()
