from __future__ import annotations

import gzip
import hashlib
import json
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from scripts import build_cve_search_db as search_db_builder
from scripts import cve_search_runtime as search_runtime


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def cve_record(
    cve: str,
    *,
    title: str,
    summary: str,
    severity: str = "high",
    score: float = 8.1,
    published: str = "2025-01-02",
    kev: bool = False,
    ecosystem: str = "software/application",
    archetypes: list[str] | None = None,
    affected_data: list[dict[str, object]] | None = None,
    stable_markdown: bool = False,
) -> dict[str, object]:
    archetype_values = archetypes or ["input-validation", "generic-remediation"]
    markdown: list[dict[str, object]] = []
    recipe_kind = "composed"
    if stable_markdown:
        recipe_kind = "markdown-override"
        markdown = [
            {
                "cve": cve,
                "maturity": "stable",
                "content_markdown": "Reviewed remediation guidance.",
            }
        ]
    return {
        "cve": cve,
        "title": title,
        "summary": summary,
        "severity": severity,
        "score": score,
        "published": published,
        "kev": kev,
        "ecosystem": ecosystem,
        "archetype": archetype_values[0],
        "archetypes": archetype_values,
        "affected_data": affected_data or [],
        "products": [],
        "recipe_kind": recipe_kind,
        "markdown": markdown,
    }


def write_catalog(root: Path, shards: dict[str, list[dict[str, object]]]) -> Path:
    catalog = root / "catalog"
    inventory: list[dict[str, object]] = []
    record_count = 0
    for relative, records in sorted(shards.items()):
        payload = b"".join(canonical_json_bytes(record) for record in records)
        compressed = gzip.compress(payload, mtime=0)
        path = catalog / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(compressed)
        inventory.append(
            {
                "path": relative,
                "records": len(records),
                "sha256": hashlib.sha256(compressed).hexdigest(),
                "bytes": len(compressed),
                "uncompressed_bytes": len(payload),
            }
        )
        record_count += len(records)
    shard_set_sha256 = hashlib.sha256(
        canonical_json_bytes([{"path": row["path"], "sha256": row["sha256"]} for row in inventory])
    ).hexdigest()
    manifest = {
        "schema_version": 2,
        "catalog_updated_at": "2026-08-26T12:00:00Z",
        "totals": {"catalog_records": record_count, "shards": len(inventory)},
        "shard_set_sha256": shard_set_sha256,
        "shard_manifest": inventory,
    }
    catalog.mkdir(parents=True, exist_ok=True)
    (catalog / "manifest.json").write_bytes(canonical_json_bytes(manifest))
    return catalog


class CVESearchRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        records_2025 = [
            cve_record(
                "CVE-2025-2001",
                title="Contoso Controller request flaw",
                summary="A malformed network request reaches the controller.",
                severity="medium",
                score=6.4,
                published="2025-09-10",
                ecosystem="network/appliance",
                archetypes=["request-routing", "generic-remediation"],
            ),
            cve_record(
                "CVE-2025-2002",
                title="Widget Agent remote execution",
                summary="Memory corruption permits remote code execution.",
                severity="critical",
                score=9.8,
                published="2025-10-11",
                kev=True,
                ecosystem="software/application",
                archetypes=["memory-safety", "remote-code-execution"],
                affected_data=[{"vendor": "Example Vendor", "product": "Orchid Router"}],
                stable_markdown=True,
            ),
        ]
        catalog = write_catalog(
            self.root,
            {
                "shards/2024/0001.jsonl.gz": [
                    cve_record(
                        "CVE-2024-1001",
                        title="Acme Secure Gateway validation flaw",
                        summary="A parser accepts malformed gateway requests.",
                        published="2024-05-01",
                        affected_data=[{"vendor": "Acme Corporation", "product": "Secure Gateway"}],
                    )
                ],
                "shards/2025/0002.jsonl.gz": records_2025,
            },
        )
        self.database = self.root / "runtime-search.sqlite3"
        self.build_result = search_db_builder.build_search_database(catalog, self.database)
        self.database_sha256 = hashlib.sha256(self.database.read_bytes()).hexdigest()

    def runtime(self, database: Path | None = None, **overrides: object) -> search_runtime.CVESearchRuntime:
        target = database or self.database
        target_sha256 = (
            hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else self.database_sha256
        )
        arguments: dict[str, object] = {
            "expected_revision": self.build_result["shard_set_sha256"],
            "expected_record_count": self.build_result["records"],
            "expected_manifest_sha256": self.build_result["manifest_sha256"],
            "expected_database_sha256": target_sha256,
        }
        arguments.update(overrides)
        return search_runtime.CVESearchRuntime(target, **arguments)

    def test_searches_title_product_and_archetype_without_loading_a_browser_index(self) -> None:
        runtime = self.runtime()

        title = runtime.search("secure gateway")
        product = runtime.search("orchid router")
        archetype = runtime.search("memory safety")

        self.assertEqual([row["cve"] for row in title["results"]], ["CVE-2024-1001"])
        self.assertEqual([row["cve"] for row in product["results"]], ["CVE-2025-2002"])
        self.assertEqual([row["cve"] for row in archetype["results"]], ["CVE-2025-2002"])
        preview = product["results"][0]
        self.assertEqual(
            set(preview),
            {
                "cve",
                "title",
                "severity",
                "score",
                "published",
                "ecosystem",
                "kev",
                "archetype",
                "archetypes",
                "has_markdown",
                "shard",
            },
        )
        self.assertTrue(preview["has_markdown"])
        self.assertEqual(preview["shard"], "shards/2025/0002.jsonl.gz")

    def test_browse_prefix_exact_and_tri_state_filters_report_exact_totals(self) -> None:
        runtime = self.runtime()

        browse = runtime.search("", limit=2)
        prefix = runtime.search("cve-2025-2")
        exact = runtime.search("cve-2025-2001")
        filtered = runtime.search("", severity="critical", published_year=2025, kev=True)
        non_kev = runtime.search("", kev=False)

        self.assertEqual([row["cve"] for row in browse["results"]], ["CVE-2025-2002", "CVE-2025-2001"])
        self.assertEqual(browse["total_matches"], 3)
        self.assertTrue(browse["truncated"])
        self.assertEqual({row["cve"] for row in prefix["results"]}, {"CVE-2025-2001", "CVE-2025-2002"})
        self.assertEqual(prefix["total_matches"], 2)
        self.assertFalse(prefix["truncated"])
        self.assertEqual([row["cve"] for row in exact["results"]], ["CVE-2025-2001"])
        self.assertEqual([row["cve"] for row in filtered["results"]], ["CVE-2025-2002"])
        self.assertEqual(non_kev["total_matches"], 2)
        self.assertTrue(all(not row["kev"] for row in non_kev["results"]))

    def test_fts_syntax_is_reduced_to_literal_bounded_terms(self) -> None:
        runtime = self.runtime()

        ordinary = runtime.search("gateway")
        syntax_like = runtime.search("gateway OR products:*")
        injection_like = runtime.search("gateway') OR 1=1 --")

        self.assertEqual(ordinary["total_matches"], 1)
        self.assertEqual(syntax_like, {"results": [], "total_matches": 0, "truncated": False})
        self.assertEqual(injection_like, {"results": [], "total_matches": 0, "truncated": False})
        self.assertEqual(runtime.search("")["total_matches"], 3)
        with self.assertRaises(search_runtime.CVESearchQueryError):
            runtime.search("* : --")

    def test_rejects_metadata_revision_count_and_manifest_mismatches(self) -> None:
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(expected_revision="0" * 64)
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(expected_record_count=4)
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(expected_manifest_sha256="f" * 64)
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(expected_database_sha256="e" * 64)

        changed_metadata = self.root / "changed-metadata.sqlite3"
        shutil.copy2(self.database, changed_metadata)
        with closing(sqlite3.connect(changed_metadata)) as connection:
            connection.execute("UPDATE metadata SET value = '4' WHERE key = 'record_count'")
            connection.commit()
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(changed_metadata)

    def test_rejects_wrong_application_schema_corruption_and_oversize_policy(self) -> None:
        wrong_application = self.root / "wrong-application.sqlite3"
        shutil.copy2(self.database, wrong_application)
        with closing(sqlite3.connect(wrong_application)) as connection:
            connection.execute("PRAGMA application_id = 1")
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(wrong_application)

        wrong_schema = self.root / "wrong-schema.sqlite3"
        shutil.copy2(self.database, wrong_schema)
        with closing(sqlite3.connect(wrong_schema)) as connection:
            connection.execute("DROP INDEX cves_newest_idx")
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(wrong_schema)

        wrong_constraints = self.root / "wrong-constraints.sqlite3"
        shutil.copy2(self.database, wrong_constraints)
        with closing(sqlite3.connect(wrong_constraints)) as connection:
            connection.execute("PRAGMA writable_schema = ON")
            connection.execute(
                "UPDATE sqlite_schema SET sql = replace(sql, "
                "'kev INTEGER NOT NULL CHECK (kev IN (0, 1))', 'kev INTEGER NOT NULL') "
                "WHERE name = 'cves'"
            )
            connection.execute("PRAGMA writable_schema = OFF")
            connection.commit()
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(wrong_constraints)

        incomplete_fts = self.root / "incomplete-fts.sqlite3"
        shutil.copy2(self.database, incomplete_fts)
        with closing(sqlite3.connect(incomplete_fts)) as connection:
            connection.execute("DELETE FROM cve_fts_docsize WHERE id = (SELECT max(id) FROM cves)")
            connection.commit()
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(incomplete_fts)

        corrupt = self.root / "corrupt.sqlite3"
        corrupt.write_bytes(b"not a sqlite database")
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(corrupt)
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(self.root / "missing.sqlite3")
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(max_database_bytes=self.database.stat().st_size - 1)

    def test_trusted_file_digest_rejects_interior_fts_posting_loss(self) -> None:
        incomplete_fts = self.root / "interior-fts-loss.sqlite3"
        shutil.copy2(self.database, incomplete_fts)
        with closing(sqlite3.connect(incomplete_fts)) as connection:
            row = connection.execute(
                "SELECT id, cve, title, summary, ecosystem, archetypes, products "
                "FROM cves WHERE id = 2"
            ).fetchone()
            saved_docsize = connection.execute("SELECT sz FROM cve_fts_docsize WHERE id = 2").fetchone()[0]
            connection.execute(
                "INSERT INTO cve_fts(cve_fts, rowid, cve, title, summary, ecosystem, archetypes, products) "
                "VALUES('delete', ?, ?, ?, ?, ?, ?, ?)",
                row,
            )
            connection.execute("INSERT INTO cve_fts_docsize(id, sz) VALUES(2, ?)", (saved_docsize,))
            connection.commit()
            missing = connection.execute(
                "SELECT 1 FROM cve_fts WHERE cve_fts MATCH ? AND rowid = 2",
                ('"CVE-2025-2001"',),
            ).fetchone()
            self.assertIsNone(missing)
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")

        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(incomplete_fts, expected_database_sha256=self.database_sha256)

    def test_connections_are_immutable_query_only_and_hardened(self) -> None:
        runtime = self.runtime()
        connection = runtime._connect(runtime._clock() + 1.0)
        try:
            self.assertEqual(connection.execute("PRAGMA query_only").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA trusted_schema").fetchone()[0], 0)
            self.assertEqual(connection.execute("PRAGMA cache_size").fetchone()[0], -4096)
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute("DELETE FROM cves")
            with self.assertRaises(sqlite3.OperationalError) as extension_error:
                connection.load_extension(str(self.root / "missing-extension"))
            self.assertIn("not authorized", str(extension_error.exception).casefold())
            connection.execute("PRAGMA query_only = OFF")
            self.assertEqual(connection.execute("PRAGMA query_only").fetchone()[0], 0)
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute("DELETE FROM cves")
        finally:
            connection.close()
        self.assertTrue(runtime._database_uri.endswith("?mode=ro&immutable=1"))

        with closing(sqlite3.connect(self.database)) as writable:
            writable.execute("UPDATE metadata SET value = '4' WHERE key = 'record_count'")
            writable.commit()
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            runtime.search("")

    def test_rejects_linked_database_paths_when_the_platform_supports_them(self) -> None:
        linked_database = self.root / "linked-search.sqlite3"
        try:
            linked_database.symlink_to(self.database)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"file symlinks are unavailable: {exc}")
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            self.runtime(linked_database)

    def test_progress_handler_cancels_queries_at_the_deadline(self) -> None:
        runtime = self.runtime()
        clock_calls = 0

        def advancing_clock() -> float:
            nonlocal clock_calls
            clock_calls += 1
            return 0.0 if clock_calls <= 2 else 2.0

        runtime._clock = advancing_clock
        with mock.patch.object(search_runtime, "PROGRESS_HANDLER_STEPS", 1):
            with self.assertRaises(search_runtime.CVESearchTimeoutError):
                runtime.search("gateway", deadline=1.0)
        self.assertGreater(clock_calls, 2)

    def test_query_and_resource_bounds_fail_closed(self) -> None:
        runtime = self.runtime()
        invalid_calls = (
            lambda: runtime.search("x" * 121),
            lambda: runtime.search(None),
            lambda: runtime.search(0),
            lambda: runtime.search("one two three four five six seven eight nine"),
            lambda: runtime.search("x" * 65),
            lambda: runtime.search("gateway", severity="low"),
            lambda: runtime.search("gateway", published_year=1998),
            lambda: runtime.search("gateway", published_year=True),
            lambda: runtime.search("gateway", kev=1),
            lambda: runtime.search("gateway", limit=0),
            lambda: runtime.search("gateway", limit=101),
            lambda: runtime.search("gateway", timeout_seconds=11.0),
        )
        for call in invalid_calls:
            with self.subTest(call=call), self.assertRaises(search_runtime.CVESearchQueryError):
                call()
        with self.assertRaises(search_runtime.CVESearchTimeoutError):
            runtime.search("gateway", deadline=runtime._clock() - 1.0)


if __name__ == "__main__":
    unittest.main()
