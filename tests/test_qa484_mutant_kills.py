from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from datetime import date
from pathlib import Path
from types import ModuleType

from scripts.generate_agentic_source_freshness_watch import DUE_WATCH_FAILURE
from tests.test_evaluate_agentic_incident_response_decision import (
    _cli_argv,
    _minimal_pack,
    _monitor_clear_request,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "qa-484-r2"
MUTANTS_PATH = FIXTURE_ROOT / "mutants.json"
MUTANT_DIR = FIXTURE_ROOT / "mutants"
LOG_PATH = FIXTURE_ROOT / "logs" / "mutant-receipt.md"
IR_PROFILE = REPO_ROOT / "data" / "assurance" / "agentic-incident-response-profile.json"
MCP_PROFILE = REPO_ROOT / "data" / "assurance" / "mcp-risk-coverage-profile.json"


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _apply_mutant(source: Path, dest: Path, old: str, new: str) -> None:
    text = source.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise AssertionError(f"{source} must contain the mutant needle exactly once, found {text.count(old)}")
    dest.write_text(text.replace(old, new, 1), encoding="utf-8")


def _decision(module: ModuleType, request: dict[str, object]) -> str:
    return str(
        module.evaluate_agentic_incident_response_decision(_minimal_pack(), request)["decision"]
    )


def _cli_decision(module: ModuleType, *flags: str) -> str:
    request = module.request_from_args(module.parse_args(_cli_argv(*flags)))
    return _decision(module, request)


def _json_decision(module: ModuleType, payload: dict[str, object]) -> str:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "runtime-request.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        request = module.request_from_args(module.parse_args(["--runtime-request", str(path)]))
    return _decision(module, request)


def _scenario(kind: str, module: ModuleType) -> object:
    if kind == "evaluator_cli_access":
        return _cli_decision(module, "--agent-can-access-monitors")
    if kind == "evaluator_cli_tamper":
        return _cli_decision(module, "--monitor-tampering-or-outage")
    if kind == "evaluator_cli_resume":
        return _cli_decision(module, "--resume-without-verified-containment")
    if kind == "evaluator_json_false_access":
        return _json_decision(module, _monitor_clear_request(agent_can_access_monitors="false"))
    if kind == "evaluator_json_false_tamper":
        return _json_decision(module, _monitor_clear_request(monitor_tampering_or_outage="false"))
    if kind == "evaluator_json_false_resume":
        return _json_decision(
            module, _monitor_clear_request(resume_without_verified_containment="false")
        )
    if kind == "evaluator_missing_access":
        payload = _monitor_clear_request()
        del payload["agent_can_access_monitors"]
        return _json_decision(module, payload)
    if kind == "evaluator_missing_tamper":
        payload = _monitor_clear_request()
        del payload["monitor_tampering_or_outage"]
        return _json_decision(module, payload)
    if kind == "evaluator_missing_resume":
        payload = _monitor_clear_request()
        del payload["resume_without_verified_containment"]
        return _json_decision(module, payload)
    if kind == "ir_assigned_class":
        return "uninstructed-control-compromise" in module.assigned_incident_classes(
            {"id": "wf", "title": "demo", "mcp_context": []},
            None,
        )
    if kind == "ir_containment":
        actions = module.containment_actions_for(
            {"id": "wf", "title": "demo", "mcp_context": []},
            ["uninstructed-control-compromise"],
        )
        return [
            "isolate_monitors_from_agent_access" in actions,
            "verify_monitors_logging_egress_and_shutdown_before_resume" in actions,
        ]
    if kind == "ir_tabletop":
        profile = module.load_json(IR_PROFILE)
        return any(
            row.get("id") == "uninstructed-control-compromise-monitor-access"
            for row in module.tabletop_cases(profile)
        )
    if kind == "mcp06_aliases":
        profile = module.load_json(MCP_PROFILE)
        rows = {str(row.get("id")): row for row in module.build_risk_coverage(profile)}
        return rows["MCP06"].get("aliases")
    if kind == "watch_review_decision":
        decision, _ = module.review_decision(date(2026, 8, 1), 30, date(2026, 8, 15), 3, False)
        return decision
    if kind == "watch_structural_failures":
        return module.structural_failures([DUE_WATCH_FAILURE, "profile schema_version must be 1.0"])
    if kind == "watch_build_pack_unfiltered":
        source = module.structural_failures.__code__.co_filename
        text = Path(source).read_text(encoding="utf-8")
        return "failures = structural_failures(" in text
    raise AssertionError(f"unknown mutant kind {kind}")


CONTROL_EXPECTED = {
    "evaluator_cli_access": "kill_session_and_escalate_board",
    "evaluator_cli_tamper": "kill_session_and_escalate_board",
    "evaluator_cli_resume": "hold_for_forensics",
    "evaluator_json_false_access": "monitor_no_incident",
    "evaluator_json_false_tamper": "monitor_no_incident",
    "evaluator_json_false_resume": "monitor_no_incident",
    "evaluator_missing_access": "contain_and_open_war_room",
    "evaluator_missing_tamper": "contain_and_open_war_room",
    "evaluator_missing_resume": "contain_and_open_war_room",
    "ir_assigned_class": True,
    "ir_containment": [True, True],
    "ir_tabletop": True,
    "mcp06_aliases": ["Prompt Injection via Contextual Payloads"],
    "watch_review_decision": "current",
    "watch_structural_failures": ["profile schema_version must be 1.0"],
    "watch_build_pack_unfiltered": True,
}

MUTANT_EXPECTED = {
    "M0": False,
    "M2": "review_due",
    "M3": [DUE_WATCH_FAILURE, "profile schema_version must be 1.0"],
    "E1": "monitor_no_incident",
    "E2": "monitor_no_incident",
    "E3": "monitor_no_incident",
    "E4": "kill_session_and_escalate_board",
    "E4b": "kill_session_and_escalate_board",
    "E4c": "hold_for_forensics",
    "E5": "contain_and_open_war_room",
    "E5b": "contain_and_open_war_room",
    "E5c": "contain_and_open_war_room",
    "E5d": "monitor_no_incident",
    "E5e": "monitor_no_incident",
    "E5f": "monitor_no_incident",
    "G1": False,
    "G2": [False, False],
    "G3": False,
    "A1": None,
}


class Qa484MutantKillTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        payload = json.loads(MUTANTS_PATH.read_text(encoding="utf-8"))
        cls.mutants = payload["mutants"]
        cls.rows: list[dict[str, object]] = []

    def test_control_then_named_mutant_kills_match_receipt(self) -> None:
        MUTANT_DIR.mkdir(parents=True, exist_ok=True)
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        rows: list[str] = [
            "| item | mutant | control | mutant actual | expected mutant | killed |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for spec in self.mutants:
            mutant_id = str(spec["id"])
            kind = str(spec["kind"])
            target = REPO_ROOT / str(spec["target"])
            with self.subTest(mutant=mutant_id):
                control_module = _load_module(f"control_{mutant_id}", target)
                control_actual = _scenario(kind, control_module)
                self.assertEqual(control_actual, CONTROL_EXPECTED[kind])
                with tempfile.TemporaryDirectory() as tmpdir:
                    mutant_copy = Path(tmpdir) / target.name
                    shutil.copy2(target, mutant_copy)
                    _apply_mutant(mutant_copy, mutant_copy, str(spec["old"]), str(spec["new"]))
                    committed = MUTANT_DIR / mutant_id / target.name
                    self.assertTrue(committed.exists(), f"missing committed mutant copy {committed}")
                    self.assertEqual(
                        mutant_copy.read_text(encoding="utf-8"),
                        committed.read_text(encoding="utf-8"),
                    )
                    mutant_module = _load_module(f"mutant_{mutant_id}", committed)
                    mutant_actual = _scenario(kind, mutant_module)
                self.assertEqual(mutant_actual, MUTANT_EXPECTED[mutant_id])
                self.assertNotEqual(mutant_actual, control_actual)
                killed = mutant_actual != control_actual and mutant_actual == MUTANT_EXPECTED[mutant_id]
                rows.append(
                    "| {id} | {kind} | {control} | {actual} | {expected} | {killed} |".format(
                        id=mutant_id,
                        kind=kind,
                        control=control_actual,
                        actual=mutant_actual,
                        expected=MUTANT_EXPECTED[mutant_id],
                        killed="yes" if killed else "NO",
                    )
                )
        receipt = (
            "# QA-484 round-2 mutant receipt\n\n"
            + "\n".join(rows)
            + "\n\n"
            + "M1 is the overdue fixture at `tests/fixtures/source-freshness/`; "
            + "killed by `test_written_pack_omits_editorial_due_failures`.\n"
            + "M2b (`validate_coverage` due_count flipped) is equivalent and is not killed separately.\n"
        )
        self.assertEqual(LOG_PATH.read_text(encoding="utf-8"), receipt)
        self.assertIn("| E5 | evaluator_cli_access |", receipt)
        self.assertIn("| E5d | evaluator_missing_access |", receipt)
        self.assertNotIn("| NO |", receipt)


if __name__ == "__main__":
    unittest.main()
