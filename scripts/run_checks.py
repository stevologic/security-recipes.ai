#!/usr/bin/env python3
"""Run local lint and test checks before site or container builds."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def run_command(argv: list[str], *, dry_run: bool = False) -> None:
    printable = " ".join(argv)
    print(f"+ {printable}", flush=True)
    if dry_run:
        return
    subprocess.run(argv, cwd=REPO_ROOT, check=True)


def node_binary() -> str:
    configured = os.environ.get("NODE_BINARY", "").strip()
    if configured:
        return configured
    node = shutil.which("node")
    if node:
        return node
    raise RuntimeError("node was not found on PATH; install Node.js or run this through the CI/container toolchain")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Print checks without running them.")
    args = parser.parse_args()

    python = sys.executable
    run_command([python, "-m", "ruff", "check", "."], dry_run=args.dry_run)
    run_command(
        [
            python,
            "-m",
            "compileall",
            "-q",
            "mcp_server.py",
            "scripts",
            "tools",
            "tests",
        ],
        dry_run=args.dry_run,
    )
    run_command([python, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"], dry_run=args.dry_run)

    node = node_binary()
    for script in sorted((REPO_ROOT / "assets" / "js").glob("*.js")):
        run_command([node, "--check", str(script.relative_to(REPO_ROOT))], dry_run=args.dry_run)
    for test_script in sorted((REPO_ROOT / "tests").glob("test_*.js")):
        run_command([node, "--test", str(test_script.relative_to(REPO_ROOT))], dry_run=args.dry_run)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
