from __future__ import annotations

import re
import shlex
import subprocess
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK_ROOT = REPO_ROOT / "content" / "security-remediation"
SCRIPT_ROOT = REPO_ROOT / "scripts"
FENCE_RE = re.compile(r"^```(?:bash|sh|shell)\s*\n(.*?)^```", re.MULTILINE | re.DOTALL)
EVALUATOR_RE = re.compile(r"scripts/(evaluate_[A-Za-z0-9_]+\.py)")
SPECIALIZED_EXCLUSIONS = {
    "evaluate_cve_intelligence_intake.py",
    "evaluate_recipe_routing.py",
}


@dataclass(frozen=True)
class DocumentedScenario:
    page: Path
    script_name: str
    command: tuple[str, ...]
    expected_decision: str


def _normalize_command(block: str) -> list[str]:
    command = re.sub(r"\\\r?\n", " ", block).strip()
    lines = [line.strip() for line in command.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if len(lines) != 1:
        raise AssertionError("evaluator command fences must contain exactly one shell command")
    tokens = shlex.split(lines[0], posix=True)
    if not tokens:
        raise AssertionError("evaluator command fence is empty")
    if Path(tokens[0]).name.lower() in {"python", "python3", "python.exe", "python3.exe", "py", "py.exe"}:
        tokens[0] = sys.executable
    return tokens


def documented_scenarios() -> list[DocumentedScenario]:
    scenarios: list[DocumentedScenario] = []
    for page in sorted(PLAYBOOK_ROOT.rglob("*.md")):
        source = page.read_text(encoding="utf-8")
        for block in FENCE_RE.findall(source):
            match = EVALUATOR_RE.search(block)
            if not match:
                continue
            command = _normalize_command(block)
            try:
                expected = command[command.index("--expect-decision") + 1]
            except (ValueError, IndexError) as exc:
                raise AssertionError(
                    f"{page.relative_to(REPO_ROOT)} documents {match.group(1)} without --expect-decision"
                ) from exc
            scenarios.append(
                DocumentedScenario(
                    page=page,
                    script_name=match.group(1),
                    command=tuple(command),
                    expected_decision=expected,
                )
            )
    return scenarios


class DocumentedEvaluatorScenarioTests(unittest.TestCase):
    maxDiff = None

    def test_every_specialized_evaluator_has_an_executable_documented_scenario(self) -> None:
        restored = {
            path.name
            for path in SCRIPT_ROOT.glob("evaluate_*.py")
            if path.name not in SPECIALIZED_EXCLUSIONS
        }
        covered = {scenario.script_name for scenario in documented_scenarios()}
        self.assertSetEqual(restored, covered)

    def test_documented_scenarios_execute_with_the_promised_decision(self) -> None:
        scenarios = documented_scenarios()
        self.assertGreaterEqual(len(scenarios), 33)
        decision_families: set[str] = set()
        failures: list[str] = []
        for scenario in scenarios:
            result = subprocess.run(
                scenario.command,
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            output = f"{result.stdout}\n{result.stderr}"
            if result.returncode != 0 or scenario.expected_decision not in output:
                failures.append(
                    "\n".join(
                        [
                            f"{scenario.page.relative_to(REPO_ROOT)}: {scenario.script_name}",
                            f"command: {shlex.join(scenario.command)}",
                            f"expected: {scenario.expected_decision}",
                            f"exit: {result.returncode}",
                            output.strip(),
                        ]
                    )
                )
            decision = scenario.expected_decision
            if decision.startswith("allow") or decision in {"approve_guarded_pilot", "eval_ready", "replay_pass", "telemetry_ready"}:
                decision_families.add("allow")
            elif decision.startswith("hold"):
                decision_families.add("hold")
            elif decision.startswith(("deny", "kill")) or decision == "replay_fail":
                decision_families.add("deny")
        self.assertFalse(failures, "\n\n".join(failures))
        self.assertSetEqual({"allow", "hold", "deny"}, decision_families)


if __name__ == "__main__":
    unittest.main()
