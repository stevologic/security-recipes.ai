from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agent_memory_boundary_decision import (
    evaluate_agent_memory_boundary_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agent-memory-boundary-pack.json"
MODEL_PATH = REPO_ROOT / "data" / "assurance" / "agent-memory-boundary-model.json"
VECTOR_INDEX_CONTROLS = (
    "tenant_scope_in_index_query",
    "trust_tiers_isolated",
    "raw_similarity_scores_withheld",
    "source_embeddings_reconciled",
)


def _vector_read(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "memory_class_id": "vector-embedding-memory",
        "operation": "read",
        "tenant_id": "tenant-123",
        "source_id": "finding-source-1",
        "provenance_hash": "example-source-hash",
        "tenant_scope_in_index_query": True,
        "trust_tiers_isolated": True,
        "raw_similarity_scores_withheld": True,
        "source_embeddings_reconciled": True,
    }
    request.update(overrides)
    return request


class AgentMemoryLlm09VectorIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))
        cls.model = json.loads(MODEL_PATH.read_text(encoding="utf-8"))

    def test_source_pack_records_llm09_2026(self) -> None:
        self.assertEqual(self.model["last_reviewed"], "2026-11-25")
        standard_ids = [row["id"] for row in self.model["standards_alignment"]]
        self.assertIn("owasp-llm-top-10-2026", standard_ids)
        self.assertIn("owasp-llm09-vector-embedding-weaknesses-2026", standard_ids)
        vector = next(row for row in self.model["memory_classes"] if row["id"] == "vector-embedding-memory")
        for control in VECTOR_INDEX_CONTROLS:
            self.assertIn(control, vector["required_controls"])

    def test_complete_vector_read_still_holds_for_admission_review(self) -> None:
        result = evaluate_agent_memory_boundary_decision(self.pack, _vector_read())
        self.assertEqual(result["decision"], "hold_for_memory_admission_review")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["violations"], [])

    def test_tenant_id_without_in_index_scope_is_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack, _vector_read(tenant_scope_in_index_query=False)
        )
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])
        self.assertIn("tenant_scope_in_index_query", result["violations"])

    def test_mixed_trust_index_without_isolation_is_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack, _vector_read(trust_tiers_isolated=False)
        )
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])
        self.assertIn("trust_tiers_isolated", result["violations"])

    def test_raw_similarity_scores_are_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack, _vector_read(raw_similarity_scores_withheld=False)
        )
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])
        self.assertIn("raw_similarity_scores_withheld", result["violations"])

    def test_embeddings_that_outlive_sources_are_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack, _vector_read(source_embeddings_reconciled=False)
        )
        self.assertEqual(result["decision"], "deny_runtime_memory_write")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["violations"], ["source_embeddings_reconciled"])

    def test_omitted_vector_index_flags_fail_closed(self) -> None:
        request = _vector_read()
        for control in VECTOR_INDEX_CONTROLS:
            request.pop(control)
        result = evaluate_agent_memory_boundary_decision(self.pack, request)
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])
        for control in VECTOR_INDEX_CONTROLS:
            self.assertIn(control, result["violations"])

    def test_unparseable_vector_index_flags_fail_closed(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read(
                tenant_scope_in_index_query="maybe",
                trust_tiers_isolated="not-a-bool",
                raw_similarity_scores_withheld="unknown",
                source_embeddings_reconciled="later",
            ),
        )
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])
        for control in VECTOR_INDEX_CONTROLS:
            self.assertIn(control, result["violations"])

    def test_ephemeral_scratchpad_does_not_require_vector_index_controls(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            {
                "workflow_id": "vulnerable-dependency-remediation",
                "memory_class_id": "ephemeral-scratchpad",
                "operation": "write",
            },
        )
        self.assertEqual(result["decision"], "allow_ephemeral_memory")
        self.assertTrue(result["allowed"])


if __name__ == "__main__":
    unittest.main()
