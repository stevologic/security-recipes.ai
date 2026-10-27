from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from unittest.mock import patch

from scripts.cve_catalog_data_paths import CatalogDiffDecision


REPO_ROOT = Path(__file__).resolve().parents[1]
PIPELINE_PATH = REPO_ROOT / "scripts" / "run_generator_pipeline.py"
SPEC = importlib.util.spec_from_file_location("run_generator_pipeline", PIPELINE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery guard
    raise RuntimeError(f"could not load {PIPELINE_PATH}")
PIPELINE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PIPELINE
SPEC.loader.exec_module(PIPELINE)

CATALOG_VALIDATION_ENV = ("CVE_CATALOG_VALIDATION", "CVE_CATALOG_VALIDATION_BASE")


@contextmanager
def isolated_catalog_validation_env(
    *,
    flag: str | None = None,
    base: str | None = None,
) -> Iterator[None]:
    previous = {key: os.environ.get(key) for key in CATALOG_VALIDATION_ENV}
    try:
        for key in CATALOG_VALIDATION_ENV:
            os.environ.pop(key, None)
        if flag is not None:
            os.environ["CVE_CATALOG_VALIDATION"] = flag
        if base is not None:
            os.environ["CVE_CATALOG_VALIDATION_BASE"] = base
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def fake_catalog_diff(*, data_only: bool) -> CatalogDiffDecision:
    return CatalogDiffDecision(
        data_only=data_only,
        sha_matches=True,
        expected_sha="0" * 40,
        actual_sha="0" * 40,
        paths=("static/api/cve-catalog/manifest.json",),
        rejected_paths=() if data_only else ("mcp_server.py",),
        unsafe_paths=(),
        reason="test catalog diff",
    )


def synthetic_generator(name: str, output: str) -> PIPELINE.Generator:
    return PIPELINE.Generator(
        name=name,
        script=Path(f"scripts/generate_{name}.py"),
        output=Path(output),
    )


def load_script_module(name: str, filename: str):
    path = REPO_ROOT / "scripts" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - import machinery guard
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class GeneratorPipelineTests(unittest.TestCase):
    def test_content_metrics_are_checkout_newline_independent(self) -> None:
        modules = [
            load_script_module(
                "generate_context_poisoning_guard_pack_test",
                "generate_context_poisoning_guard_pack.py",
            ),
            load_script_module(
                "generate_secure_context_trust_pack_test",
                "generate_secure_context_trust_pack.py",
            ),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            lf_path = Path(temp_dir) / "lf.txt"
            crlf_path = Path(temp_dir) / "crlf.txt"
            lf_path.write_bytes(b"alpha\nbeta\n")
            crlf_path.write_bytes(b"alpha\r\nbeta\r\n")
            for module in modules:
                self.assertEqual(
                    module.canonical_text_byte_count(lf_path),
                    module.canonical_text_byte_count(crlf_path),
                )

    def test_inventory_contains_all_check_capable_generators(self) -> None:
        generators = PIPELINE.discover_generators(REPO_ROOT)
        self.assertEqual(57, len(generators))
        self.assertEqual(57, len({generator.output for generator in generators}))

    def test_ownership_and_every_content_hash_reference_are_exact(self) -> None:
        generators = PIPELINE.discover_generators(REPO_ROOT)
        self.assertEqual(57, PIPELINE.validate_ownership(generators, REPO_ROOT))
        self.assertGreaterEqual(PIPELINE.validate_hashed_references(generators, REPO_ROOT), 821)

    def test_content_hash_dependency_graph_is_acyclic(self) -> None:
        generators = PIPELINE.discover_generators(REPO_ROOT)
        graph = PIPELINE.dependency_graph(generators, REPO_ROOT)
        tiers = PIPELINE.topological_tiers(graph)
        self.assertEqual({generator.name for generator in generators}, {name for tier in tiers for name in tier})
        self.assertGreater(len(tiers), 1, "the evidence pipeline should preserve meaningful dependency tiers")

        forbidden_backward_edges = {
            "agentic_standards_crosswalk": {
                "agent_trust_fabric_pack",
                "agentic_control_plane_blueprint",
                "enterprise_trust_center_export",
            },
            "agentic_posture_snapshot": {"enterprise_trust_center_export"},
            "agentic_protocol_conformance_pack": {"enterprise_trust_center_export"},
            "mcp_risk_coverage_pack": {"enterprise_trust_center_export"},
            "agentic_threat_radar": {"agent_handoff_boundary_pack"},
        }
        for consumer, forbidden in forbidden_backward_edges.items():
            self.assertTrue(
                graph[consumer].isdisjoint(forbidden),
                f"{consumer} restored a backward hash edge: {sorted(graph[consumer] & forbidden)}",
            )
        self.assertIn(
            "agentic_threat_radar",
            graph["agent_handoff_boundary_pack"],
            "handoff evidence must continue to consume the threat radar",
        )

    def test_emitted_mcp_tool_claims_are_registered(self) -> None:
        generators = PIPELINE.discover_generators(REPO_ROOT)
        self.assertGreaterEqual(PIPELINE.validate_mcp_data_paths(generators, REPO_ROOT), 50)
        self.assertGreaterEqual(PIPELINE.validate_evaluator_data_paths(generators, REPO_ROOT), 30)
        claim_count = PIPELINE.validate_mcp_tool_claims(generators, REPO_ROOT)
        self.assertGreaterEqual(claim_count, 50)
        registered = PIPELINE.registered_mcp_tools(REPO_ROOT)
        self.assertIn("recipes_playbook_get", registered)
        self.assertIn("recipes_playbook_plan", registered)

    def test_hash_validator_rejects_missing_and_mismatched_references(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "data" / "source.json"
            output = root / "data" / "evidence" / "consumer.json"
            source.parent.mkdir(parents=True)
            output.parent.mkdir(parents=True)
            source.write_text('{"ok":true}\n', encoding="utf-8")
            output.write_text(
                json.dumps({"input": {"path": "data/source.json", "sha256": "0" * 64}}),
                encoding="utf-8",
            )
            generator = PIPELINE.Generator("consumer", Path("scripts/generate_consumer.py"), Path("data/evidence/consumer.json"))
            with self.assertRaisesRegex(PIPELINE.PipelineError, "SHA-256 mismatch"):
                PIPELINE.validate_hashed_references([generator], root)

            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            output.write_text(
                json.dumps({"input": {"path": "data/source.json", "sha256": expected}}),
                encoding="utf-8",
            )
            source.unlink()
            with self.assertRaisesRegex(PIPELINE.PipelineError, "referenced file is missing"):
                PIPELINE.validate_hashed_references([generator], root)

    def test_write_reconciles_output_after_generator_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scripts = root / "scripts"
            evidence = root / "data" / "evidence"
            scripts.mkdir(parents=True)
            evidence.mkdir(parents=True)
            (root / "mcp_server.py").write_text(
                'class ServerConfig:\n    evidence_path = "./data/evidence/new.json"\n',
                encoding="utf-8",
            )
            (scripts / "generate_new.py").write_text(
                "from pathlib import Path\n"
                "import argparse\n"
                'DEFAULT_OUTPUT = Path("data/evidence/new.json")\n'
                "parser = argparse.ArgumentParser()\n"
                'parser.add_argument("--check", action="store_true")\n'
                "args = parser.parse_args()\n"
                "path = Path.cwd() / DEFAULT_OUTPUT\n"
                "rendered = '{}\\n'\n"
                "if args.check:\n"
                "    raise SystemExit(0 if path.is_file() and path.read_text(encoding='utf-8') == rendered else 1)\n"
                "path.parent.mkdir(parents=True, exist_ok=True)\n"
                "path.write_text(rendered, encoding='utf-8', newline='\\n')\n",
                encoding="utf-8",
            )
            old_output = evidence / "old.json"
            old_output.write_text("{}\n", encoding="utf-8")
            old_generator = PIPELINE.Generator(
                "old",
                Path("scripts/generate_old.py"),
                Path("data/evidence/old.json"),
            )
            ownership = scripts / "generated-output-ownership.json"
            ownership.write_text(
                json.dumps(PIPELINE.ownership_payload([old_generator]), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            self.assertEqual(0, PIPELINE.regenerate(root))
            self.assertFalse(old_output.exists())
            self.assertTrue((evidence / "new.json").is_file())
            generators = PIPELINE.discover_generators(root)
            self.assertEqual(1, PIPELINE.validate_ownership(generators, root))

    def test_all_generated_artifacts_are_fresh(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(PIPELINE_PATH),
                "--check",
                "--scope",
                "auto",
                "--repo-root",
                str(REPO_ROOT),
            ],
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(
            0,
            result.returncode,
            f"all 57 deterministic generators must pass --check\n{result.stdout}",
        )

    def test_catalog_only_stale_karen_gated_outputs_are_pending_not_failing(self) -> None:
        """Reproduce sync validation 40479848520 on catalog PR #434 head e43e7b45.

        The unscoped freshness check failed `0 != 1` because three Karen-gated
        evidence packs were stale after the catalog-only split. Scoped
        catalog-only validation must report them as pending on #441, not fail.
        """

        generators = PIPELINE.discover_generators(REPO_ROOT)
        stale = (
            "context_egress_boundary_pack",
            "context_poisoning_guard_pack",
            "secure_context_trust_pack",
        )
        failures = [(name, 1) for name in stale]
        unscoped = PIPELINE.classify_check_failures(generators, failures, scope="all")
        self.assertTrue(unscoped.failed)
        self.assertEqual(unscoped.blocking, stale)
        self.assertIn("failed --check", unscoped.message)

        scoped = PIPELINE.classify_check_failures(generators, failures, scope="cve-owned")
        self.assertFalse(scoped.failed)
        self.assertEqual(scoped.blocking, ())
        self.assertEqual(scoped.pending, stale)
        self.assertIn("automation/cve-generated-outputs", scoped.message)
        self.assertIn("needs karen-qa", scoped.message)
        for name in stale:
            self.assertTrue(PIPELINE.generator_is_karen_gated(next(g for g in generators if g.name == name)))

    def test_full_freshness_still_blocks_on_main_when_evidence_is_stale(self) -> None:
        generators = PIPELINE.discover_generators(REPO_ROOT)
        decision = PIPELINE.classify_check_failures(
            generators,
            [("secure_context_trust_pack", 1)],
            scope="all",
        )
        self.assertTrue(decision.failed)
        self.assertEqual(decision.blocking, ("secure_context_trust_pack",))

    def test_missing_validation_base_fails_closed(self) -> None:
        self.assertEqual(PIPELINE.resolve_check_scope("all"), "all")
        self.assertEqual(PIPELINE.resolve_check_scope("cve-owned"), "cve-owned")
        with isolated_catalog_validation_env():
            self.assertFalse(PIPELINE.should_scope_freshness_to_cve_owned())
            self.assertEqual(PIPELINE.resolve_check_scope("auto"), "all")
        with isolated_catalog_validation_env(flag="true", base=None):
            with patch.object(PIPELINE, "evaluate_git_catalog_diff") as mocked:
                self.assertFalse(PIPELINE.should_scope_freshness_to_cve_owned())
                self.assertEqual(PIPELINE.resolve_check_scope("auto"), "all")
                mocked.assert_not_called()

    def test_env_alone_does_not_relax_when_diff_is_not_data_only(self) -> None:
        not_data_only = fake_catalog_diff(data_only=False)
        with isolated_catalog_validation_env(flag="true", base="origin/main"):
            with (
                patch.object(PIPELINE.subprocess, "check_output", return_value="abc\n"),
                patch.object(
                    PIPELINE,
                    "evaluate_git_catalog_diff",
                    return_value=not_data_only,
                ) as mocked,
            ):
                self.assertFalse(PIPELINE.should_scope_freshness_to_cve_owned())
                mocked.assert_called_once()
                self.assertEqual(PIPELINE.resolve_check_scope("auto"), "all")

    def test_catalog_only_data_only_diff_scopes_to_cve_owned(self) -> None:
        data_only = fake_catalog_diff(data_only=True)
        with isolated_catalog_validation_env(flag="true", base="origin/main"):
            with (
                patch.object(PIPELINE.subprocess, "check_output", return_value="abc\n"),
                patch.object(
                    PIPELINE,
                    "evaluate_git_catalog_diff",
                    return_value=data_only,
                ) as mocked,
            ):
                self.assertTrue(PIPELINE.should_scope_freshness_to_cve_owned())
                mocked.assert_called_once()
                self.assertEqual(PIPELINE.resolve_check_scope("auto"), "cve-owned")

    def test_stale_cve_owned_outputs_block_under_catalog_scope(self) -> None:
        catalog = synthetic_generator(
            "catalog_shard",
            "static/api/cve-catalog/manifest.json",
        )
        self.assertFalse(PIPELINE.generator_is_karen_gated(catalog))
        decision = PIPELINE.classify_check_failures(
            [catalog],
            [("catalog_shard", 1)],
            scope="cve-owned",
        )
        self.assertTrue(decision.failed)
        self.assertEqual(decision.blocking, ("catalog_shard",))
        self.assertEqual(decision.pending, ())

    def test_unrelated_outputs_are_not_treated_as_karen_gated(self) -> None:
        other = synthetic_generator("orphan_pack", "data/orphan/not-gated.json")
        self.assertFalse(PIPELINE.generator_is_karen_gated(other))
        decision = PIPELINE.classify_check_failures(
            [other],
            [("orphan_pack", 1)],
            scope="cve-owned",
        )
        self.assertTrue(decision.failed)
        self.assertEqual(decision.blocking, ("orphan_pack",))
        self.assertEqual(decision.pending, ())

    def test_mixed_stale_outputs_keep_cve_owned_blocking(self) -> None:
        generators = [
            synthetic_generator("catalog_shard", "static/api/cve-catalog/manifest.json"),
            synthetic_generator(
                "secure_context_trust_pack",
                "data/evidence/secure-context-trust-pack.json",
            ),
        ]
        decision = PIPELINE.classify_check_failures(
            generators,
            [("catalog_shard", 1), ("secure_context_trust_pack", 1)],
            scope="cve-owned",
        )
        self.assertTrue(decision.failed)
        self.assertEqual(decision.blocking, ("catalog_shard",))
        self.assertEqual(decision.pending, ("secure_context_trust_pack",))


if __name__ == "__main__":
    unittest.main()
