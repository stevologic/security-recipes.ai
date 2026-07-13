from __future__ import annotations

import asyncio
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_server import (
    PlaybookRegistry,
    ServerConfig,
    load_config,
    recipes_playbook_get,
    recipes_playbook_plan,
    recipes_playbooks_list,
    recipes_server_info,
)


def run(coro):
    return asyncio.run(coro)


def playbook(
    playbook_id: str = "dependency-remediation",
    *,
    category: str = "vulnerability-remediation",
) -> dict:
    return {
        "id": playbook_id,
        "title": "Dependency vulnerability remediation",
        "page": f"/security-remediation/{playbook_id}/",
        "category": category,
        "summary": "Bound, patch, verify, and document a vulnerable dependency change.",
        "phases": [
            {
                "label": "Signal",
                "title": "Normalize the finding",
                "detail": "Preserve the advisory identity and affected range.",
            },
            {
                "label": "Scope",
                "title": "Scope the finding",
                "detail": "Confirm the affected package and repository boundary.",
            },
            {
                "label": "Decision",
                "title": "Select the safe target",
                "detail": "Choose the smallest supported remediation target.",
            },
            {
                "label": "Action",
                "title": "Apply the remediation",
                "detail": "Update the smallest manifest and lockfile scope.",
            },
            {
                "label": "Proof",
                "title": "Verify the result",
                "detail": "Run targeted tests and prove the vulnerable version is absent.",
            },
        ],
        "gate": {
            "question": "Is the vulnerable version absent and do targeted tests pass?",
            "pass": "Prepare the bounded remediation handoff.",
            "stop": "Stop when no supported fixed version exists.",
        },
        "evidence": ["dependency diff", "verification log"],
        "outputs": ["repository patch", "verification report"],
        "python": {
            "scenario": "Plan a bounded dependency remediation.",
            "command": (
                "python scripts/security_recipes_remediation_suite.py playbook start "
                f"--playbook {playbook_id} --workspace . --finding finding.json "
                f"--run-dir .security-recipes/runs/{playbook_id}"
            ),
        },
        "file_patterns": ["**/package.json", "**/package-lock.json"],
        "recipe_queries": ["dependency CVE patch", "lockfile remediation"],
    }


def registry_payload() -> dict:
    incident = playbook("incident-containment", category="incident-response")
    incident.update(
        {
            "title": "Security incident containment",
            "summary": "Preserve evidence, contain the affected service, and verify recovery.",
            "python": {
                "scenario": "Plan a bounded incident-containment handoff.",
                "command": (
                    "python scripts/security_recipes_remediation_suite.py playbook start "
                    "--playbook incident-containment --workspace . --finding finding.json "
                    "--run-dir .security-recipes/runs/incident-containment"
                ),
            },
            "file_patterns": ["**/*.log", "**/incident-*.json"],
            "recipe_queries": ["incident containment", "evidence preservation"],
        }
    )
    return {
        "schema_version": "1.0",
        "suite_version": "2026.07",
        "playbooks": [
            playbook(),
            incident,
        ],
    }


class PlaybookRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.registry_path = Path(self.tempdir.name) / "playbooks.json"
        self.registry_path.write_text(json.dumps(registry_payload()), encoding="utf-8")
        self.registry = PlaybookRegistry(str(self.registry_path))

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_default_and_toml_configuration(self) -> None:
        self.assertEqual(
            ServerConfig().playbook_registry_path,
            "./data/remediation_suite/playbooks.json",
        )
        config_path = Path(self.tempdir.name) / "mcp-server.toml"
        config_path.write_text(
            'playbook_registry_path = "./fixtures/playbooks.json"\n',
            encoding="utf-8",
        )
        self.assertEqual(
            load_config(str(config_path)).playbook_registry_path,
            "./fixtures/playbooks.json",
        )

    def test_bundled_registry_validates_and_plans_every_profile_shape(self) -> None:
        path = Path(__file__).resolve().parents[1] / "data" / "remediation_suite" / "playbooks.json"
        bundled = PlaybookRegistry(str(path))
        metadata = bundled.metadata()
        self.assertTrue(metadata["available"], metadata.get("error"))
        self.assertGreaterEqual(metadata["playbook_count"], 75)
        listed = bundled.list_playbooks(limit=PlaybookRegistry.MAX_LIMIT)
        self.assertEqual(listed["matched_count"], metadata["playbook_count"])
        for item in listed["results"]:
            plan = bundled.plan(item["id"], "offline contract verification")
            self.assertIsNotNone(plan)
            assert plan is not None
            self.assertTrue(plan["phase_checklist"])
            self.assertTrue(plan["gate_checklist"])
            self.assertTrue(plan["evidence_checklist"])
            self.assertTrue(plan["python_contract"])

    def test_list_is_concise_searchable_filterable_and_reloadable(self) -> None:
        result = self.registry.list_playbooks(query="lockfile", limit=10)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["matched_count"], 1)
        self.assertEqual(result["schema_version"], "1.0")
        self.assertEqual(result["suite_version"], "2026.07")
        self.assertEqual(
            set(result["results"][0]),
            {
                "id",
                "title",
                "page",
                "category",
                "summary",
                "phase_count",
                "evidence_count",
                "output_count",
                "python_available",
            },
        )

        incident = self.registry.list_playbooks(category="INCIDENT-RESPONSE")
        self.assertEqual([item["id"] for item in incident["results"]], ["incident-containment"])

        self.registry_path.write_text("not JSON anymore", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            self.registry.list_playbooks(limit=1)
        self.assertFalse(self.registry.metadata()["available"])

        replacement = registry_payload()
        replacement["suite_version"] = "2026.08"
        replacement["playbooks"] = [replacement["playbooks"][1]]
        self.registry_path.write_text(json.dumps(replacement), encoding="utf-8")
        reloaded = self.registry.list_playbooks(limit=10)
        self.assertEqual(reloaded["suite_version"], "2026.08")
        self.assertEqual([item["id"] for item in reloaded["results"]], ["incident-containment"])
        self.assertIsNone(self.registry.get_playbook("dependency-remediation"))

        self.registry_path.unlink()
        missing = self.registry.metadata()
        self.assertFalse(missing["available"])
        with self.assertRaisesRegex(ValueError, "missing or not a regular file"):
            self.registry.list_playbooks(limit=10)

    def test_get_returns_complete_isolated_contract(self) -> None:
        result = self.registry.get_playbook("dependency-remediation")
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(set(PlaybookRegistry.REQUIRED_FIELDS) - set(result), set())
        self.assertIn("--playbook dependency-remediation", result["python"]["command"])
        result["phases"][0]["title"] = "mutated by caller"
        fresh = self.registry.get_playbook("dependency-remediation")
        self.assertEqual(fresh["phases"][0]["title"], "Normalize the finding")
        self.assertIsNone(self.registry.get_playbook("missing-playbook"))

    def test_plan_is_deterministic_agent_ready_and_side_effect_free(self) -> None:
        first = self.registry.plan("dependency-remediation", " GHSA-xxxx in package.json ")
        second = self.registry.plan("dependency-remediation", "GHSA-xxxx in package.json")
        self.assertEqual(first, second)
        assert first is not None
        self.assertEqual(first["finding"], "GHSA-xxxx in package.json")
        self.assertTrue(first["planning_only"])
        self.assertEqual(first["side_effects"], {"writes": False, "network": False})
        self.assertEqual(
            [item["phase"]["label"] for item in first["phase_checklist"]],
            ["Signal", "Scope", "Decision", "Action", "Proof"],
        )
        self.assertTrue(all(item["status"] == "pending" for item in first["phase_checklist"]))
        self.assertEqual(len(first["gate_checklist"]), 1)
        self.assertEqual(len(first["evidence_checklist"]), 2)
        self.assertIn("playbook start", first["python_contract"]["command"])
        self.assertEqual(first["output_contract"][0], "repository patch")

    def test_rejects_invalid_ids_limits_and_schema(self) -> None:
        with self.assertRaisesRegex(ValueError, "playbook_id must match"):
            self.registry.get_playbook("../dependency-remediation")
        with self.assertRaisesRegex(ValueError, "limit must be between"):
            self.registry.list_playbooks(limit=0)
        with self.assertRaisesRegex(ValueError, "limit must be between"):
            self.registry.list_playbooks(limit=101)

        invalid_path = Path(self.tempdir.name) / "invalid.json"
        invalid = registry_payload()
        del invalid["playbooks"][0]["python"]
        invalid_path.write_text(json.dumps(invalid), encoding="utf-8")
        metadata = PlaybookRegistry(str(invalid_path)).metadata()
        self.assertFalse(metadata["available"])
        self.assertIn("missing required fields", metadata["error"])

    def test_rejects_incompatible_profile_shapes(self) -> None:
        cases: dict[str, tuple[dict, str]] = {}

        wrong_page = copy.deepcopy(registry_payload())
        wrong_page["playbooks"][0]["page"] = "/playbooks/dependency-remediation/"
        cases["wrong page"] = (wrong_page, "page must be")

        short_workflow = copy.deepcopy(registry_payload())
        short_workflow["playbooks"][0]["phases"] = short_workflow["playbooks"][0]["phases"][:2]
        cases["short workflow"] = (short_workflow, "exactly five phases")

        legacy_gate = copy.deepcopy(registry_payload())
        legacy_gate["playbooks"][0]["gate"] = {"criteria": ["tests pass"]}
        cases["legacy gate"] = (legacy_gate, "gate.question")

        object_evidence = copy.deepcopy(registry_payload())
        object_evidence["playbooks"][0]["evidence"] = [{"id": "verification-log"}]
        cases["object evidence"] = (object_evidence, "evidence item")

        legacy_python = copy.deepcopy(registry_payload())
        legacy_python["playbooks"][0]["python"] = {
            "entrypoint": "python -m security_recipes",
            "subcommand": "dependency-remediation",
        }
        cases["legacy python"] = (legacy_python, "python.scenario")

        wrong_command = copy.deepcopy(registry_payload())
        wrong_command["playbooks"][0]["python"]["command"] = "python shallow_wrapper.py"
        cases["wrong command"] = (wrong_command, "canonical playbook start interface")

        for label, (payload, expected_error) in cases.items():
            with self.subTest(label=label):
                path = Path(self.tempdir.name) / f"invalid-{label.replace(' ', '-')}.json"
                path.write_text(json.dumps(payload), encoding="utf-8")
                metadata = PlaybookRegistry(str(path)).metadata()
                self.assertFalse(metadata["available"])
                self.assertIn(expected_error, metadata["error"])

    def test_mcp_tools_expose_registry_and_return_validation_errors(self) -> None:
        with patch("mcp_server.playbook_registry", self.registry):
            listed = run(recipes_playbooks_list(query="dependency", limit=5))
            fetched = run(recipes_playbook_get("dependency-remediation"))
            planned = run(recipes_playbook_plan("dependency-remediation", "CVE-2026-0001"))
            invalid = run(recipes_playbooks_list(limit=0))
            info = run(recipes_server_info())

        self.assertEqual(listed["count"], 1)
        self.assertTrue(fetched["found"])
        self.assertEqual(fetched["playbook"]["id"], "dependency-remediation")
        self.assertTrue(planned["found"])
        self.assertFalse(planned["side_effects"]["writes"])
        self.assertEqual(invalid["count"], 0)
        self.assertIn("limit must be between", invalid["error"])
        self.assertTrue(info["playbook_registry"]["available"])
        self.assertEqual(info["playbook_registry"]["playbook_count"], 2)
        self.assertIn("playbook_registry_path", info)


if __name__ == "__main__":
    unittest.main()
