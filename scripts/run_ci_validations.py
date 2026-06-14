#!/usr/bin/env python3
"""Run Python validation commands checked by the GitHub Action.

This runner intentionally derives its command list from
`.github/workflows/hugo.yml` so local validation stays aligned with CI.
"""

from __future__ import annotations

import argparse
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
    def is_check(self) -> bool:
        return "--check" in self.args

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


def run_command(command: WorkflowCommand, python: str, dry_run: bool) -> None:
    rel_script = command.script.relative_to(REPO_ROOT).as_posix()
    printable = shlex.join(["python3", rel_script, *command.args])
    print(f"+ {printable}", flush=True)
    if dry_run:
        return

    subprocess.run(command.argv(python), cwd=REPO_ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", type=Path, default=DEFAULT_WORKFLOW)
    parser.add_argument("--python", default=sys.executable, help="Python executable to use for child scripts.")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without running them.")
    args = parser.parse_args()

    workflow_path = args.workflow if args.workflow.is_absolute() else REPO_ROOT / args.workflow
    commands = extract_workflow_commands(workflow_path)

    print(f"Running {len(commands)} Python validation command(s) from {workflow_path.relative_to(REPO_ROOT)}.")
    for command in commands:
        run_command(command, args.python, args.dry_run)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
