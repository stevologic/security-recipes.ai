#!/usr/bin/env python3
"""Apply on-disk mutants to a sandbox and record named-test kills."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from tests.cve_sync_mutants.mutants import KILLERS, MUTANTS, SANDBOX_FILES


ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = Path(__file__).resolve().parent / "logs"
PYTHON = sys.executable


def needle_line(text: str, needle: str) -> int:
    index = text.find(needle)
    if index < 0:
        return 0
    return text.count("\n", 0, index) + 1


def copy_sandbox(dest: Path) -> None:
    for relative in SANDBOX_FILES:
        source = ROOT / relative
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def apply_mutant(dest: Path, relative: str, old: str, new: str) -> int:
    path = dest / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"vacuous mutant: old text missing in {relative}")
    if text.count(old) != 1:
        raise SystemExit(f"ambiguous mutant: old text matches {text.count(old)} times in {relative}")
    line = needle_line(text, old)
    mutated = text.replace(old, new, 1)
    if mutated == text:
        raise SystemExit(f"vacuous mutant: replacement made no change in {relative}")
    path.write_text(mutated, encoding="utf-8")
    return line


def run_unittest(cwd: Path, test: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "-m", "unittest", test],
        cwd=cwd,
        env={
            **{key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
            "PYTHONPATH": str(cwd),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def unique_killers() -> list[str]:
    seen: list[str] = []
    for test in KILLERS.values():
        if test not in seen:
            seen.append(test)
    return seen


def assertion_tail(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in reversed(lines):
        if line.startswith("AssertionError") or line.startswith("FAIL:"):
            return line[:400]
    for line in reversed(lines):
        if "expected" in line.lower() or "actual=" in line:
            return line[:400]
    return (lines[-1] if lines else "")[:400]


def is_behavioral_kill(proc: subprocess.CompletedProcess[str]) -> bool:
    if proc.returncode == 0:
        return False
    blob = f"{proc.stdout}\n{proc.stderr}"
    if "ModuleNotFoundError" in blob or "Failed to import test module" in blob:
        return False
    return "FAIL:" in blob or "AssertionError" in blob


def write_log(name: str, proc: subprocess.CompletedProcess[str]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / f"{name}.log").write_text(
        f"exit={proc.returncode}\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n",
        encoding="utf-8",
    )


def main() -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    control_tests = unique_killers()
    print("CONTROL: running named killer tests on clean tree")
    control = subprocess.run(
        [PYTHON, "-m", "unittest", *control_tests],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    write_log("control", control)
    if control.returncode != 0:
        sys.stderr.write(control.stdout + control.stderr)
        sys.stderr.write("CONTROL FAILED\n")
        return 1
    print("CONTROL: green")

    rows: list[str] = [
        "mutant\tfile:line\tkilling_test\tstatus\tactual_vs_expected"
    ]
    killed = 0
    for mutant_id, relative, old, new in MUTANTS:
        killer = KILLERS[mutant_id]
        source_text = (ROOT / relative).read_text(encoding="utf-8")
        line = needle_line(source_text, old)
        with tempfile.TemporaryDirectory(prefix=f"{mutant_id}-") as tmp:
            dest = Path(tmp)
            copy_sandbox(dest)
            apply_mutant(dest, relative, old, new)
            proc = run_unittest(dest, killer)
        write_log(mutant_id, proc)
        if proc.returncode == 0:
            status = "SURVIVED"
            actual = f"actual=exit 0 expected=nonzero ({killer} still passed)"
            print(f"{mutant_id}: SURVIVED")
        elif is_behavioral_kill(proc):
            status = "KILLED"
            killed += 1
            actual = (
                f"actual=exit {proc.returncode} expected=nonzero; "
                f"{assertion_tail(proc.stderr or proc.stdout)}"
            )
            print(f"{mutant_id}: KILLED by {killer} (exit {proc.returncode})")
        else:
            status = "ERROR"
            actual = (
                f"actual=exit {proc.returncode} but not an assertion kill; "
                f"{assertion_tail(proc.stderr or proc.stdout)}"
            )
            print(f"{mutant_id}: ERROR (not counted as kill)")
        rows.append(f"{mutant_id}\t{relative}:{line}\t{killer}\t{status}\t{actual}")

    summary = [
        f"control_exit={control.returncode}",
        f"killed={killed}/{len(MUTANTS)}",
        f"survivors={len(MUTANTS) - killed}",
    ]
    (LOG_DIR / "receipt.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    (LOG_DIR / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary))
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
