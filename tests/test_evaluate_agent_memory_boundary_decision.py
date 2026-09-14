from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agent_memory_boundary_decision import (
    evaluate_agent_memory_boundary_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agent-memory-boundary-pack.json"


def _receipt_write(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "memory_class_id": "run-receipt-evidence",
        "operation": "write",
        "tenant_id": "tenant-123",
        "provenance_hash": "example-source-hash",
    }
    request.update(overrides)
    return request


def _vector_read(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "memory_class_id": "vector-embedding-memory",
        "operation": "read",
        "tenant_id": "tenant-123",
    }
    request.update(overrides)
    return request


class AgentMemoryBoundaryVectorIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_receipt_write_is_allowed_when_vector_signals_are_unspecified(self) -> None:
        result = evaluate_agent_memory_boundary_decision(self.pack, _receipt_write())
        self.assertEqual(result["decision"], "allow_append_only_evidence_memory")
        self.assertTrue(result["allowed"])

    def test_vector_read_holds_when_vector_signals_are_unspecified(self) -> None:
        result = evaluate_agent_memory_boundary_decision(self.pack, _vector_read())
        self.assertEqual(result["decision"], "hold_for_memory_admission_review")
        self.assertFalse(result["allowed"])

    def test_post_retrieval_tenant_scope_is_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read(tenant_scope_post_retrieval_only=True),
        )
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("inside the index query" in item for item in result["violations"])
        )

    def test_mixed_trust_index_without_isolation_is_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read(mixed_trust_index_without_isolation=True),
        )
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("mixed-trust content" in item for item in result["violations"])
        )

    def test_raw_similarity_scores_hold_for_review(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read(raw_similarity_scores_returned_to_client=True),
        )
        self.assertEqual(result["decision"], "hold_for_memory_admission_review")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("raw similarity scores" in item for item in result["violations"])
        )

    def test_embeddings_that_outlive_source_hold_for_review(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read(embeddings_persist_after_source_delete=True),
        )
        self.assertEqual(result["decision"], "hold_for_memory_admission_review")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("deleted when their source is deleted" in item for item in result["violations"])
        )


if __name__ == "__main__":
    unittest.main()
