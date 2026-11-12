#!/usr/bin/env python3
"""Re-run Karen's mut kit against the live workflows (ControlTests × 6)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


KIT = Path(__file__).resolve().parent
REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(KIT))
from mutants import EXTRA, MUTANTS, SH, VA  # noqa: E402

REPS = 6
BEH = ["tests.test_exact_sha_build_status_harness.ExactShaBuildStatusControlTests"]
SRC = [
    "tests.test_automation_shepherd_workflow",
    "tests.test_cve_catalog_validation_workflow",
]
LOGDIR = KIT / "logs"
DIFFDIR = KIT / "diffs"
SEED = [
    ".github/workflows/automation-shepherd.yml",
    ".github/workflows/cve-catalog-validate.yml",
    "tests/test_exact_sha_build_status_harness.py",
    "tests/test_automation_shepherd_workflow.py",
    "tests/test_cve_catalog_validation_workflow.py",
    "tests/fixtures/exact_sha_build_status/gh_stub.py",
]


def seed(dst: Path) -> None:
    for rel in SEED:
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, target)
    (dst / "tests" / "__init__.py").write_text("", encoding="utf-8")


def apply_mutant(dst: Path, mid: str, f: str, old: str, new: str) -> None:
    edits = [(f, old, new)]
    extra = EXTRA.get(mid)
    if extra:
        edits.append(extra)
    for ff, o, n in edits:
        path = dst / ff
        text = path.read_text(encoding="utf-8")
        count = text.count(o)
        if count != 1:
            raise SystemExit(f"{mid}: anchor count {count} in {ff}")
        path.write_text(text.replace(o, n, 1), encoding="utf-8")


def run_mods(wt: Path, mods: list[str]) -> tuple[int, list[str], str]:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "-v", *mods],
            cwd=wt,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        return 99, ["TIMEOUT"], "TIMEOUT"
    fails = sorted(set(re.findall(r"^(?:FAIL|ERROR): (\w+) ", proc.stderr, re.M)))
    return proc.returncode, fails, proc.stderr


def one(item: tuple[str, Path]) -> tuple[str, dict]:
    mid, wt = item
    beh_k = 0
    src_k = 0
    bf: set[str] = set()
    sf: set[str] = set()
    last = ""
    for _ in range(REPS):
        rc, fails, err = run_mods(wt, BEH)
        if rc != 0:
            beh_k += 1
            bf |= set(fails)
            last = err
        rc2, fails2, _err2 = run_mods(wt, SRC)
        if rc2 != 0:
            src_k += 1
            sf |= set(fails2)
    (LOGDIR / f"{mid}.beh.log").write_text(last, encoding="utf-8")
    line = f"{mid}\tbeh {beh_k}/{REPS} {sorted(bf)}\tsrc {src_k}/{REPS} {sorted(sf)}"
    print(line, flush=True)
    return mid, {
        "behavioural_fail_reps": beh_k,
        "beh_tests": sorted(bf),
        "source_text_fail_reps": src_k,
        "src_tests": sorted(sf),
        "killed": beh_k == REPS,
    }


def main() -> int:
    LOGDIR.mkdir(parents=True, exist_ok=True)
    DIFFDIR.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="karen-kit-"))
    targets: list[tuple[str, Path]] = []
    ctl = staging / "CONTROL"
    seed(ctl)
    targets.append(("CONTROL", ctl))
    for mid, f, old, new in MUTANTS:
        wt = staging / mid
        seed(wt)
        apply_mutant(wt, mid, f, old, new)
        diff = subprocess.run(["diff", "-u", str(ctl / f), str(wt / f)], capture_output=True, text=True)
        extra = EXTRA.get(mid)
        extra_diff = ""
        if extra:
            extra_diff = subprocess.run(
                ["diff", "-u", str(ctl / extra[0]), str(wt / extra[0])],
                capture_output=True,
                text=True,
            ).stdout
        (DIFFDIR / f"{mid}.diff").write_text(diff.stdout + extra_diff, encoding="utf-8")
        targets.append((mid, wt))
    only = sys.argv[1:]
    if only:
        targets = [t for t in targets if t[0] in only]
    with ThreadPoolExecutor(4) as pool:
        results = dict(pool.map(one, targets))
    (KIT / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    lines = ["id\tbeh\tsrc\tkilled"]
    survivors = []
    for mid, row in results.items():
        killed = mid == "CONTROL" or row["behavioural_fail_reps"] == REPS
        if mid != "CONTROL" and row["behavioural_fail_reps"] != REPS:
            survivors.append(mid)
        lines.append(
            f"{mid}\t{row['behavioural_fail_reps']}/{REPS}\t{row['source_text_fail_reps']}/{REPS}\t{killed}"
        )
    summary = "\n".join(lines) + "\n"
    if survivors:
        summary += "SURVIVORS\t" + ",".join(survivors) + "\n"
    else:
        summary += "SURVIVORS\tnone\n"
    (KIT / "summary.txt").write_text(summary, encoding="utf-8")
    print(summary)
    shutil.rmtree(staging, ignore_errors=True)
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
