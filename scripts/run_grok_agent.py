#!/usr/bin/env python3
"""Run the Grok Build CLI headlessly against a checked-in prompt file."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

try:
    from scripts.cve_ai_enrichment import DEFAULT_MODEL
except ModuleNotFoundError:  # Direct ``python scripts/run_grok_agent.py``.
    from cve_ai_enrichment import DEFAULT_MODEL  # type: ignore[no-redef]

DEFAULT_GROK_BIN = Path.home() / ".grok" / "bin" / "grok"
ACTIONS_GIT_NAME = "github-actions[bot]"
ACTIONS_GIT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"


def resolve_grok_binary() -> str:
    found = shutil.which("grok")
    if found:
        return found
    if DEFAULT_GROK_BIN.is_file() and os.access(DEFAULT_GROK_BIN, os.X_OK):
        return str(DEFAULT_GROK_BIN)
    raise FileNotFoundError(
        "grok CLI is not on PATH; run scripts/install_grok_cli.sh first."
    )


def git_config_value(key: str) -> str:
    result = subprocess.run(
        ["git", "config", "--get", key],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def ensure_git_identity() -> None:
    if shutil.which("git") is None:
        return
    if git_config_value("user.email") and git_config_value("user.name"):
        return
    subprocess.run(
        ["git", "config", "user.email", ACTIONS_GIT_EMAIL],
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", ACTIONS_GIT_NAME],
        check=True,
    )


def build_command(prompt: str, *, model: str, grok_bin: str) -> list[str]:
    return [
        grok_bin,
        "--no-auto-update",
        "--no-alt-screen",
        "--always-approve",
        "--output-format",
        "plain",
        "-m",
        model,
        "-p",
        prompt,
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompt-file", type=Path, required=True)
    parser.add_argument(
        "--model",
        default=os.environ.get("XAI_MODEL", "").strip() or DEFAULT_MODEL,
    )
    args = parser.parse_args(argv)

    api_key = os.environ.get("XAI_API_KEY", "").strip()
    if not api_key:
        print("XAI_API_KEY is required to run the Grok agent.", file=sys.stderr)
        return 2

    prompt = args.prompt_file.read_text(encoding="utf-8").strip()
    if not prompt:
        print(f"{args.prompt_file} is empty.", file=sys.stderr)
        return 2

    ensure_git_identity()
    command = build_command(prompt, model=args.model, grok_bin=resolve_grok_binary())
    print(
        f"Running Grok CLI model {args.model} with {args.prompt_file}.",
        flush=True,
    )
    completed = subprocess.run(command, check=False)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
