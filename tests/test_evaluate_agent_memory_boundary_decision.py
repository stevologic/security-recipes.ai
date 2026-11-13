from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.evaluate_agent_memory_boundary_decision import (
    evaluate_agent_memory_boundary_decision,
    main,
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
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "run_id": "run-ci",
    }
    request.update(overrides)
    return request


def _vector_read(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "workflow_id": "vulnerable-dependency-remediation",
        "memory_class_id": "vector-embedding-memory",
        "operation": "read",
        "tenant_id": "tenant-123",
        "provenance_hash": "example-source-hash",
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "run_id": "run-ci",
        "human_approval_record": {"id": "apr-1"},
    }
    request.update(overrides)
    return request


def _isolated_vector_read(**overrides: object) -> dict[str, object]:
    return _vector_read(
        tenant_scope_enforced_in_index_query=True,
        mixed_trust_index=False,
        returns_raw_similarity_scores=False,
        source_deleted_without_embedding_delete=False,
        retrieved_record_integrity_verified=True,
        **overrides,
    )


class AgentMemoryVectorIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pack = json.loads(PACK_PATH.read_text(encoding="utf-8"))

    def test_receipt_write_is_still_allowed(self) -> None:
        result = evaluate_agent_memory_boundary_decision(self.pack, _receipt_write())
        self.assertEqual(result["decision"], "allow_append_only_evidence_memory")
        self.assertTrue(result["allowed"])

    def test_vector_read_without_in_index_tenant_scope_is_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(self.pack, _vector_read())
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("tenant_scope_enforced_in_index_query" in item for item in result["violations"])
        )

    def test_post_retrieval_tenant_filter_is_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read(tenant_scope_enforced_in_index_query=False),
        )
        self.assertEqual(result["decision"], "deny_cross_tenant_memory")
        self.assertFalse(result["allowed"])

    def test_mixed_trust_index_is_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read(
                tenant_scope_enforced_in_index_query=True,
                mixed_trust_index=True,
                returns_raw_similarity_scores=False,
                source_deleted_without_embedding_delete=False,
            ),
        )
        self.assertEqual(result["decision"], "deny_runtime_memory_write")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("mixed_trust_index" in item for item in result["violations"]))

    def test_raw_similarity_scores_are_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read(
                tenant_scope_enforced_in_index_query=True,
                mixed_trust_index=False,
                returns_raw_similarity_scores=True,
                source_deleted_without_embedding_delete=False,
            ),
        )
        self.assertEqual(result["decision"], "deny_runtime_memory_write")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any("returns_raw_similarity_scores" in item for item in result["violations"])
        )

    def test_orphan_embeddings_are_denied(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read(
                tenant_scope_enforced_in_index_query=True,
                mixed_trust_index=False,
                returns_raw_similarity_scores=False,
                source_deleted_without_embedding_delete=True,
            ),
        )
        self.assertEqual(result["decision"], "deny_runtime_memory_write")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any(
                "source_deleted_without_embedding_delete" in item
                for item in result["violations"]
            )
        )

    def test_unverified_retrieved_record_is_held(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read(
                tenant_scope_enforced_in_index_query=True,
                mixed_trust_index=False,
                returns_raw_similarity_scores=False,
                source_deleted_without_embedding_delete=False,
            ),
        )
        self.assertEqual(result["decision"], "hold_for_memory_admission_review")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any(
                "retrieved_record_integrity_verified" in item
                for item in result["violations"]
            )
        )

    def test_isolated_vector_read_holds_for_admission(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack, _isolated_vector_read()
        )
        self.assertEqual(result["decision"], "hold_for_memory_admission_review")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["violations"], [])

    def test_customer_runtime_read_without_integrity_is_held(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            {
                "workflow_id": "vulnerable-dependency-remediation",
                "memory_class_id": "customer-runtime-memory",
                "operation": "read",
                "tenant_id": "tenant-123",
                "provenance_hash": "example-source-hash",
                "human_approval_record": {"id": "apr-1"},
            },
        )
        self.assertEqual(result["decision"], "hold_for_memory_admission_review")
        self.assertFalse(result["allowed"])
        self.assertTrue(
            any(
                "retrieved_record_integrity_verified" in item
                for item in result["violations"]
            )
        )

    def test_json_false_tokens_are_parsed(self) -> None:
        result = evaluate_agent_memory_boundary_decision(
            self.pack,
            _vector_read(
                tenant_scope_enforced_in_index_query=True,
                mixed_trust_index="false",
                returns_raw_similarity_scores="0",
                source_deleted_without_embedding_delete="no",
                retrieved_record_integrity_verified="yes",
            ),
        )
        self.assertEqual(result["decision"], "hold_for_memory_admission_review")
        self.assertEqual(result["violations"], [])

    def test_cli_denies_post_retrieval_tenant_filter(self) -> None:
        exit_code = main(
            [
                "--workflow-id",
                "vulnerable-dependency-remediation",
                "--memory-class-id",
                "vector-embedding-memory",
                "--operation",
                "read",
                "--tenant-id",
                "tenant-123",
                "--provenance-hash",
                "example-source-hash",
                "--no-tenant-scope-enforced-in-index-query",
                "--expect-decision",
                "deny_cross_tenant_memory",
            ]
        )
        self.assertEqual(exit_code, 0)

    def test_cli_holds_isolated_vector_read(self) -> None:
        exit_code = main(
            [
                "--workflow-id",
                "vulnerable-dependency-remediation",
                "--memory-class-id",
                "vector-embedding-memory",
                "--operation",
                "read",
                "--tenant-id",
                "tenant-123",
                "--provenance-hash",
                "example-source-hash",
                "--tenant-scope-enforced-in-index-query",
                "--no-mixed-trust-index",
                "--no-returns-raw-similarity-scores",
                "--no-source-deleted-without-embedding-delete",
                "--retrieved-record-integrity-verified",
                "--expect-decision",
                "hold_for_memory_admission_review",
            ]
        )
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
