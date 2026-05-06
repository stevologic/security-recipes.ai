#!/usr/bin/env python3
"""Regenerate and validate the artifacts checked by the GitHub Action.

This runner intentionally derives its command list from
`.github/workflows/hugo.yml` so local validation stays aligned with CI.
It first refreshes each generator referenced by the workflow, then replays
the workflow's Python validation/evaluation commands.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "hugo.yml"


@dataclass(frozen=True)
class WorkflowCommand:
    command: str
    line_number: int
    script: Path
    args: tuple[str, ...]

    @property
    def is_generator(self) -> bool:
        return self.script.name.startswith("generate_")

    @property
    def is_check(self) -> bool:
        return "--check" in self.args

    @property
    def is_evaluator(self) -> bool:
        return self.script.name.startswith("evaluate_")

    def argv(self, python: str) -> list[str]:
        return [python, str(self.script), *self.args]


def extract_workflow_commands(workflow_path: Path) -> list[WorkflowCommand]:
    """Extract `python3 scripts/*.py` commands from bash run blocks."""

    commands: list[WorkflowCommand] = []
    parts: list[str] = []
    start_line = 0

    for line_number, raw_line in enumerate(workflow_path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw_line.strip()

        if parts:
            if stripped and not stripped.startswith("#"):
                continued = stripped.endswith("\\")
                parts.append(stripped[:-1].strip() if continued else stripped)
                if not continued:
                    commands.append(parse_command(" ".join(parts), start_line))
                    parts = []
            continue

        if not stripped.startswith("python3 scripts/"):
            continue

        start_line = line_number
        continued = stripped.endswith("\\")
        parts = [stripped[:-1].strip() if continued else stripped]
        if not continued:
            commands.append(parse_command(parts[0], start_line))
            parts = []

    if parts:
        raise ValueError(f"Unterminated python command starting at {workflow_path}:{start_line}")

    return commands


def parse_command(command: str, line_number: int) -> WorkflowCommand:
    tokens = shlex.split(command, posix=True)
    if len(tokens) < 2 or tokens[0] != "python3" or not tokens[1].startswith("scripts/"):
        raise ValueError(f"Unsupported workflow command at line {line_number}: {command}")

    script = REPO_ROOT / Path(tokens[1])
    return WorkflowCommand(
        command=command,
        line_number=line_number,
        script=script,
        args=tuple(tokens[2:]),
    )


def build_refresh_commands(commands: list[WorkflowCommand]) -> list[WorkflowCommand]:
    """Create one refresh command per generator, ordered by first CI use."""

    refresh_commands: list[WorkflowCommand] = []
    seen: set[Path] = set()

    for command in commands:
        if not command.is_generator or command.script in seen:
            continue

        refresh_args = tuple(arg for arg in command.args if arg not in {"--check", "--update-if-stale"})
        refresh_commands.append(
            WorkflowCommand(
                command=" ".join(["python3", command.script.relative_to(REPO_ROOT).as_posix(), *refresh_args]),
                line_number=command.line_number,
                script=command.script,
                args=refresh_args,
            )
        )
        seen.add(command.script)

    return refresh_commands


def run_command(command: WorkflowCommand, python: str, dry_run: bool) -> None:
    rel_script = command.script.relative_to(REPO_ROOT).as_posix()
    printable = shlex.join(["python3", rel_script, *command.args])
    print(f"+ {printable}", flush=True)
    if dry_run:
        return

    subprocess.run(command.argv(python), cwd=REPO_ROOT, check=True)


def prepare_a2a_agent_card_fixtures(dry_run: bool) -> None:
    """Mirror the GitHub workflow's /tmp agent-card fixture setup."""

    profile_path = REPO_ROOT / "data" / "assurance" / "a2a-agent-card-trust-profile.json"
    fixture_dir = Path("/tmp")
    print("+ prepare /tmp A2A agent-card fixtures", flush=True)
    if dry_run:
        return

    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    fixture_dir.mkdir(parents=True, exist_ok=True)
    for case in profile.get("sample_agent_cards", []):
        case_id = str(case.get("id") or "").strip()
        agent_card = case.get("agent_card")
        if not case_id or not isinstance(agent_card, dict):
            continue
        (fixture_dir / f"{case_id}.json").write_text(
            json.dumps(agent_card),
            encoding="utf-8",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", type=Path, default=DEFAULT_WORKFLOW)
    parser.add_argument("--python", default=sys.executable, help="Python executable to use for child scripts.")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without running them.")
    parser.add_argument(
        "--refresh-only",
        action="store_true",
        help="Regenerate artifacts but skip the workflow's check/evaluation pass.",
    )
    parser.add_argument(
        "--skip-evaluations",
        action="store_true",
        help="Skip evaluate_*.py commands during the validation pass.",
    )
    args = parser.parse_args()

    workflow_path = args.workflow if args.workflow.is_absolute() else REPO_ROOT / args.workflow
    commands = extract_workflow_commands(workflow_path)
    refresh_commands = build_refresh_commands(commands)

    print(f"Loaded {len(commands)} Python validation commands from {workflow_path.relative_to(REPO_ROOT)}.")
    print(f"Refreshing {len(refresh_commands)} generated artifact set(s).")

    for command in refresh_commands:
        run_command(command, args.python, args.dry_run)

    if args.refresh_only:
        return 0

    validation_commands = commands
    if args.skip_evaluations:
        validation_commands = [command for command in commands if not command.is_evaluator]

    if any(command.script.name == "evaluate_a2a_agent_card_trust_decision.py" for command in validation_commands):
        prepare_a2a_agent_card_fixtures(args.dry_run)

    print(f"Running {len(validation_commands)} workflow validation command(s).")
    for command in validation_commands:
        run_command(command, args.python, args.dry_run)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
