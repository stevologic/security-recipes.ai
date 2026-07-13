from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = REPO_ROOT / "scripts" / "validate_marketplace_integrity.py"
SPEC = importlib.util.spec_from_file_location("validate_marketplace_integrity", VALIDATOR_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery guard
    raise RuntimeError(f"could not load {VALIDATOR_PATH}")
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


class MarketplaceIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        shutil.copytree(REPO_ROOT / "data" / "marketplace", self.root / "data" / "marketplace")
        shutil.copytree(
            REPO_ROOT / "static" / "marketplace-schemas",
            self.root / "static" / "marketplace-schemas",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def read_json(self, relative: str) -> dict:
        return json.loads((self.root / relative).read_text(encoding="utf-8"))

    def write_json(self, relative: str, value: dict) -> None:
        (self.root / relative).write_text(
            json.dumps(value, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def test_current_marketplace_graph_is_complete(self) -> None:
        summary = VALIDATOR.validate(REPO_ROOT)
        self.assertEqual(32, summary.input_channels)
        self.assertEqual(24, summary.output_channels)
        self.assertEqual(10, summary.report_profiles)
        self.assertEqual(27, summary.workflow_templates)
        self.assertEqual(4, summary.strategic_tracks)
        self.assertEqual(13, summary.schemas)
        self.assertGreaterEqual(summary.local_schema_references, 60)

    def test_duplicate_ids_and_workflow_references_are_rejected(self) -> None:
        inputs_path = "data/marketplace/input_channels.json"
        inputs = self.read_json(inputs_path)
        inputs["channels"][1]["id"] = inputs["channels"][0]["id"]
        self.write_json(inputs_path, inputs)

        workflows_path = "data/marketplace/workflow_templates.json"
        workflows = self.read_json(workflows_path)
        workflows["templates"][0]["default_report_profile_id"] = "missing-report"
        workflows["templates"][0]["default_output_channel_id"] = "missing-output"
        workflows["templates"][0]["default_input_channel_ids"] = ["missing-input"]
        self.write_json(workflows_path, workflows)

        with self.assertRaises(VALIDATOR.ValidationError) as raised:
            VALIDATOR.validate(self.root)
        message = str(raised.exception)
        self.assertIn("duplicate input channels ID", message)
        self.assertIn("missing-report", message)
        self.assertIn("missing-output", message)
        self.assertIn("missing-input", message)

    def test_catalog_and_readiness_references_are_rejected(self) -> None:
        catalog_path = "data/marketplace/catalog.json"
        catalog = self.read_json(catalog_path)
        catalog["strategic_tracks"][0]["pack_ids"].append("missing-pack")
        catalog["strategic_tracks"][0]["market_signal_sources"].append("missing-signal")
        self.write_json(catalog_path, catalog)

        readiness_path = "data/marketplace/readiness_profiles.json"
        readiness = self.read_json(readiness_path)
        readiness["runtime_requirements"].pop("live")
        readiness["auth_mode_details"].pop("bearer_token")
        readiness["output_driver_auth_modes"].pop("github-issue")
        self.write_json(readiness_path, readiness)

        with self.assertRaises(VALIDATOR.ValidationError) as raised:
            VALIDATOR.validate(self.root)
        message = str(raised.exception)
        self.assertIn("missing-pack", message)
        self.assertIn("missing-signal", message)
        self.assertIn("runtime_requirements is missing", message)
        self.assertIn("auth_mode_details is missing", message)
        self.assertIn("output_driver_auth_modes is missing", message)

    def test_schema_index_must_exactly_own_physical_files(self) -> None:
        source = self.root / "static" / "marketplace-schemas" / "case-file.schema.json"
        shutil.copyfile(source, source.with_name("orphan.schema.json"))
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "does not own schema files: orphan.schema.json"):
            VALIDATOR.validate(self.root)

    def test_schema_ids_applies_to_and_local_refs_must_resolve(self) -> None:
        index_path = "static/marketplace-schemas/index.json"
        index = self.read_json(index_path)
        index["schemas"][0]["applies_to"] = "data/marketplace/missing.json"
        self.write_json(index_path, index)

        schema_path = "static/marketplace-schemas/case-library.schema.json"
        schema = self.read_json(schema_path)
        schema["$id"] = "/marketplace-schemas/wrong.schema.json"
        schema["properties"]["case_files"]["items"]["$ref"] = (
            "/marketplace-schemas/case-file.schema.json#/$defs/missingDefinition"
        )
        self.write_json(schema_path, schema)

        with self.assertRaises(VALIDATOR.ValidationError) as raised:
            VALIDATOR.validate(self.root)
        message = str(raised.exception)
        self.assertIn("applies_to does not resolve", message)
        self.assertIn("$id must exactly match", message)
        self.assertIn("does not resolve", message)


if __name__ == "__main__":
    unittest.main()
