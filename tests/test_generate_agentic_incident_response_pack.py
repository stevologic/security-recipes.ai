from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.generate_agentic_incident_response_pack import (
    DEFAULT_PROFILE,
    SOURCE_REFS,
    assigned_incident_classes,
    build_pack,
    build_source_artifacts,
    containment_actions_for,
    load_json,
    load_sources,
    tabletop_cases,
    validate_profile,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "generate_agentic_incident_response_pack.py"
COMMITTED_PACK = REPO_ROOT / "data" / "evidence" / "agentic-incident-response-pack.json"
PLAYBOOKS_PATH = REPO_ROOT / "data" / "remediation_suite" / "playbooks.json"


def _fresh_pack() -> dict[str, object]:
    profile = load_json(REPO_ROOT / DEFAULT_PROFILE)
    payloads, load_failures = load_sources(REPO_ROOT, SOURCE_REFS)
    artifacts = build_source_artifacts(repo_root=REPO_ROOT, refs=SOURCE_REFS, payloads=payloads)
    failures = [*validate_profile(profile), *load_failures]
    return build_pack(
        profile=profile,
        source_payloads=payloads,
        source_artifacts=artifacts,
        generated_at="2026-11-12",
        failures=failures,
    )


class FreshIncidentResponsePackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = load_json(REPO_ROOT / DEFAULT_PROFILE)
        cls.pack = _fresh_pack()

    def test_ir_playbook_isolates_monitors_before_resume(self) -> None:
        playbooks = json.loads(PLAYBOOKS_PATH.read_text(encoding="utf-8"))
        playbook = next(
            row
            for row in playbooks["playbooks"]
            if row.get("id") == "agentic-incident-response-pack"
        )
        decision = next(phase for phase in playbook["phases"] if phase.get("label") == "Decision")
        action = next(phase for phase in playbook["phases"] if phase.get("label") == "Action")
        self.assertIn("isolate monitors from agent access", decision["detail"])
        self.assertIn("verify monitors, logging, egress allowlists, and shutdown mechanisms", action["detail"])
        self.assertIn("monitors isolated from the agent", playbook["gate"]["question"])

    def test_severity_thresholds_cover_monitor_access_and_unverified_resume(self) -> None:
        contract = self.profile["incident_contract"]
        by_severity = {row["severity"]: row for row in contract["severity_thresholds"]}
        self.assertIn(
            "agent can access or interfere with monitoring processes and logs, or monitor tampering or outage is observed",
            by_severity["sev0"]["conditions"],
        )
        self.assertIn(
            "resume is attempted without verified monitors, logging, egress allowlists, and shutdown mechanisms",
            by_severity["sev2"]["conditions"],
        )

    def test_does_not_read_the_committed_incident_response_pack(self) -> None:
        self.assertTrue(COMMITTED_PACK.exists())
        committed = json.loads(COMMITTED_PACK.read_text(encoding="utf-8"))
        self.assertNotEqual(id(self.pack), id(committed))
        self.assertIn("uninstructed-control-compromise", {row["id"] for row in self.pack["incident_classes"]})

    def test_assigned_classes_include_uninstructed_control_compromise(self) -> None:
        class_ids = assigned_incident_classes({"id": "wf", "title": "demo", "mcp_context": []}, None)
        self.assertIn("uninstructed-control-compromise", class_ids)

    def test_containment_actions_isolate_and_verify_monitors(self) -> None:
        actions = containment_actions_for(
            {"id": "wf", "title": "demo", "mcp_context": []},
            ["uninstructed-control-compromise"],
        )
        self.assertIn("isolate_monitors_from_agent_access", actions)
        self.assertIn("verify_monitors_logging_egress_and_shutdown_before_resume", actions)

    def test_tabletop_includes_monitor_access_control_compromise(self) -> None:
        cases = {row["id"]: row for row in tabletop_cases(self.profile)}
        self.assertIn("uninstructed-control-compromise-monitor-access", cases)
        self.assertEqual(
            cases["uninstructed-control-compromise-monitor-access"]["incident_class_id"],
            "uninstructed-control-compromise",
        )

    def test_fresh_pack_registers_class_containment_and_tabletop(self) -> None:
        classes = {row["id"] for row in self.pack.get("incident_classes", [])}
        self.assertIn("uninstructed-control-compromise", classes)
        source_ids = {row["id"] for row in self.pack.get("standards_alignment", [])}
        self.assertIn("nist-caissi-si-incident-readiness-2026", source_ids)
        matrix = self.pack.get("workflow_response_matrix", [])
        self.assertTrue(matrix)
        self.assertTrue(
            all("uninstructed-control-compromise" in row.get("assigned_incident_class_ids", []) for row in matrix)
        )
        self.assertTrue(
            all(
                "isolate_monitors_from_agent_access" in row.get("containment_actions", [])
                and "verify_monitors_logging_egress_and_shutdown_before_resume" in row.get("containment_actions", [])
                for row in matrix
            )
        )
        tabletop_ids = {row["id"] for row in self.pack.get("tabletop_cases", [])}
        self.assertIn("uninstructed-control-compromise-monitor-access", tabletop_ids)

    def test_temp_dir_generator_output_matches_in_memory_pack_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "agentic-incident-response-pack.json"
            generate = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--repo-root",
                    str(REPO_ROOT),
                    "--output",
                    str(output),
                    "--generated-at",
                    "2026-11-12",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(generate.returncode, 0, generate.stderr)
            written = json.loads(output.read_text(encoding="utf-8"))
            self.assertNotEqual(output.resolve(), COMMITTED_PACK.resolve())
            classes = {row["id"] for row in written.get("incident_classes", [])}
            self.assertIn("uninstructed-control-compromise", classes)
            tabletop_ids = {row["id"] for row in written.get("tabletop_cases", [])}
            self.assertIn("uninstructed-control-compromise-monitor-access", tabletop_ids)


if __name__ == "__main__":
    unittest.main()
