from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PIPELINE_PATH = REPO_ROOT / "scripts" / "run_generator_pipeline.py"
SPEC = importlib.util.spec_from_file_location("run_generator_pipeline", PIPELINE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery guard
    raise RuntimeError(f"could not load {PIPELINE_PATH}")
PIPELINE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PIPELINE
SPEC.loader.exec_module(PIPELINE)


class GeneratorPipelineTests(unittest.TestCase):
    def test_inventory_contains_all_check_capable_generators(self) -> None:
        generators = PIPELINE.discover_generators(REPO_ROOT)
        self.assertEqual(56, len(generators))
        self.assertEqual(56, len({generator.output for generator in generators}))

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
        claim_count = PIPELINE.validate_mcp_tool_claims(generators, REPO_ROOT)
        self.assertGreaterEqual(claim_count, 50)
        registered = PIPELINE.registered_mcp_tools(REPO_ROOT)
        self.assertIn("recipes_playbook_get", registered)
        self.assertIn("recipes_playbook_plan", registered)

    def test_all_generated_artifacts_are_fresh(self) -> None:
        result = subprocess.run(
            [sys.executable, str(PIPELINE_PATH), "--check", "--repo-root", str(REPO_ROOT)],
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(
            0,
            result.returncode,
            f"all 56 deterministic generators must pass --check\n{result.stdout}",
        )


if __name__ == "__main__":
    unittest.main()
