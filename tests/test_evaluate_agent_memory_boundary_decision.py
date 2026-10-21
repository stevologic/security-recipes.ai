from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agent_memory_boundary_decision import (
    evaluate_agent_memory_boundary_decision,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = REPO_ROOT / "data" / "evidence" / "agent-memory-boundary-pack.json"


def _vector_read_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "memory_class_id": "vector-embedding-memory",
        "operation": "read",
        "tenant_id": "tenant-123",
        "tenant_scope_enforcement": "in_index_query",
    }
    request.update(overrides)
    return request


class AgentMemoryVectorIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_vector_read_with_in_index_tenant_scope_holds_for_admission(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack, _vector_read_request()
        )
        self.assertEqual(result["decision"], "hold_for_memory_admission_review")
        self.assertFalse(result["allowed"])

    def test_omitted_in_index_tenant_scope_is_denied(self) -> None:
        request = _vector_read_request()
        del request["tenant_scope_enforcement"]
        result = evaluate_agent_memory_boundary_decision(self.pack, request)
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])

    def test_missing_in_index_tenant_scope_is_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read_request(tenant_scope_enforcement=""),
        )
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("tenant_scope_enforcement" in item for item in result["violations"])
        )

    def test_post_retrieval_tenant_scope_is_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read_request(tenant_scope_enforcement="post_retrieval"),
        )
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("post_retrieval" in item for item in result["violations"])
        )

    def test_mixed_trust_shared_index_is_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read_request(mixed_trust_index=True),
        )
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("mixed_trust_index" in item for item in result["violations"])
        )

    def test_raw_similarity_scores_are_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read_request(returns_raw_similarity_scores=True),
        )
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any(
                "returns_raw_similarity_scores" in item
                for item in result["violations"]
            )
        )

    def test_embeddings_retained_after_source_deletion_are_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read_request(source_deleted_embeddings_retained=True),
        )
        self.assertEqual(result["decision"], "deny_runtime_memory_write")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any(
                "source_deleted_embeddings_retained" in item
                for item in result["violations"]
            )
        )

    def test_receipt_write_is_unchanged_when_vector_controls_are_absent(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            {
                "workflow_id": "vulnerable-dependency-remediation",
                "memory_class_id": "run-receipt-evidence",
                "operation": "write",
                "tenant_id": "tenant-123",
                "provenance_hash": "example-source-hash",
            },
        )
        self.assertEqual(result["decision"], "allow_append_only_evidence_memory")
        self.assertTrue(result["allowed"])

    def test_secret_memory_still_kills_the_session(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read_request(contains_secret=True),
        )
        self.assertEqual(result["decision"], "kill_session_on_prohibited_memory")
        self.assertFalse(result["allowed"])
