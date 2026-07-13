from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK_ROOT = ROOT / "content" / "security-remediation"
REGISTRY_PATH = ROOT / "data" / "remediation_suite" / "playbooks.json"


class PlaybookDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.files = sorted(
            path
            for path in PLAYBOOK_ROOT.glob("*/_index.md")
            if path.parent != PLAYBOOK_ROOT
        )
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.profiles = cls.registry["playbooks"]

    def test_registry_exactly_covers_every_playbook(self) -> None:
        source_ids = {path.parent.name for path in self.files}
        profile_ids = {str(profile["id"]) for profile in self.profiles}

        self.assertEqual(len(self.files), 75)
        self.assertEqual(len(self.profiles), 75)
        self.assertEqual(len(profile_ids), 75, "playbook ids must be unique")
        self.assertEqual(profile_ids, source_ids)

    def test_every_profile_has_an_executable_workflow_contract(self) -> None:
        for profile in self.profiles:
            with self.subTest(playbook=profile.get("id")):
                playbook_id = str(profile["id"])
                self.assertEqual(
                    profile.get("page"),
                    f"/security-remediation/{playbook_id}/",
                )
                self.assertTrue(str(profile.get("title", "")).strip())
                self.assertTrue(str(profile.get("category", "")).strip())
                self.assertGreaterEqual(len(str(profile.get("summary", "")).strip()), 45)

                phases = profile.get("phases")
                self.assertIsInstance(phases, list)
                self.assertEqual(len(phases), 5)
                for phase in phases:
                    self.assertTrue(str(phase.get("label", "")).strip())
                    self.assertTrue(str(phase.get("title", "")).strip())
                    self.assertGreaterEqual(len(str(phase.get("detail", "")).strip()), 20)

                gate = profile.get("gate")
                self.assertIsInstance(gate, dict)
                for field in ("question", "pass", "stop"):
                    self.assertGreaterEqual(len(str(gate.get(field, "")).strip()), 20)

                self.assertGreaterEqual(len(profile.get("evidence", [])), 2)
                self.assertGreaterEqual(len(profile.get("outputs", [])), 1)
                self.assertGreaterEqual(len(profile.get("file_patterns", [])), 1)
                self.assertGreaterEqual(len(profile.get("recipe_queries", [])), 2)

                python = profile.get("python")
                self.assertIsInstance(python, dict)
                command = str(python.get("command", ""))
                self.assertIn("scripts/security_recipes_remediation_suite.py", command)
                self.assertIn("playbook start", command)
                self.assertIn(f"--playbook {playbook_id}", command)
                self.assertGreaterEqual(len(str(python.get("scenario", "")).strip()), 20)

                for pattern in profile.get("file_patterns", []):
                    normalized = str(pattern).replace("\\", "/")
                    self.assertFalse(normalized.startswith("/"))
                    self.assertNotIn("..", normalized.split("/"))

    def test_every_page_places_one_workflow_before_reference_material(self) -> None:
        marker = "{{< playbook-workflow >}}"
        for path in self.files:
            with self.subTest(playbook=path.parent.name):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(text.count(marker), 1)
                self.assertLess(text.index(marker) / max(1, len(text)), 0.6)
                self.assertNotIn("## Python remediation tool", text)
                if path.parent.name != "remediation-suite":
                    self.assertNotIn("{{< remediation-tool", text)

    def test_operational_command_prompts_are_not_blank(self) -> None:
        prompt = re.compile(
            r"^(?:Run|Regenerate|Evaluate|List|Inspect|Generate|Validate|Replay)\b.*:\s*$",
            re.IGNORECASE,
        )
        failures: list[str] = []
        for path in self.files:
            lines = path.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if not prompt.match(line.strip()):
                    continue
                following = next(
                    (candidate.strip() for candidate in lines[index + 1 :] if candidate.strip()),
                    "",
                )
                if not following.startswith(("```", "{{<", "- `", "1. ")):
                    failures.append(f"{path.relative_to(ROOT)}:{index + 1} -> {following[:70]}")
        self.assertEqual(failures, [], "command introductions need an executable example")

    def test_generator_evaluator_and_mcp_lists_are_complete(self) -> None:
        failures: list[str] = []
        for path in self.files:
            lines = path.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                stripped = line.strip()
                if re.match(r"^-\s+(?:Generator|Runtime evaluator):\s*$", stripped):
                    failures.append(f"{path.relative_to(ROOT)}:{index + 1} empty tool field")
                if "`recipes_" in stripped and stripped.endswith(" and"):
                    failures.append(f"{path.relative_to(ROOT)}:{index + 1} dangling MCP tool list")
        self.assertEqual(failures, [])

    def test_every_documented_mcp_tool_is_implemented(self) -> None:
        server_source = (ROOT / "mcp_server.py").read_text(encoding="utf-8")
        implemented = set(
            re.findall(
                r"@mcp\.tool\([^\n]*\)\s*(?:async\s+)?def\s+(recipes_[a-z0-9_]+)",
                server_source,
            )
        )
        failures: list[str] = []
        for path in self.files:
            documented = set(re.findall(r"\b(recipes_[a-z0-9_]+)\b", path.read_text(encoding="utf-8")))
            for tool_name in sorted(documented - implemented):
                failures.append(f"{path.relative_to(ROOT)}: {tool_name}")
        self.assertEqual(failures, [], "playbooks must not advertise nonexistent MCP tools")

    def test_headings_have_content(self) -> None:
        failures: list[str] = []
        for path in self.files:
            text = path.read_text(encoding="utf-8")
            sections = re.split(r"(?m)^(## .+)$", text)
            for index in range(1, len(sections), 2):
                heading = sections[index].strip()
                body = sections[index + 1].strip() if index + 1 < len(sections) else ""
                if not body:
                    failures.append(f"{path.relative_to(ROOT)}: {heading}")
        self.assertEqual(failures, [], "playbook headings must not be empty")


if __name__ == "__main__":
    unittest.main()
