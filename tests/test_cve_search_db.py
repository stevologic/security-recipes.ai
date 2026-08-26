from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from copy import deepcopy
from pathlib import Path

from scripts import build_cve_search_db as search_db


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
    affected_data: list[dict[str, object]] | None = None,
    products: list[dict[str, object]] | None = None,
    recipe_kind: str = "composed",
    markdown: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "cve": cve,
        "title": title,
        "summary": summary,
        "severity": severity,
        "score": score,
        "published": published,
        "kev": kev,
        "ecosystem": ecosystem,
        "archetype": "input-validation",
        "archetypes": ["input-validation", "generic-remediation"],
        "affected_data": affected_data or [],
        "products": products or [],
        "recipe_kind": recipe_kind,
        "markdown": markdown or [],
    }


def write_catalog(
    root: Path,
    shards: dict[str, list[dict[str, object]]],
) -> tuple[Path, dict[str, object]]:
    catalog = root / "catalog"
    entries: list[dict[str, object]] = []
    total = 0
    for relative, records in sorted(shards.items()):
        uncompressed = b"".join(canonical_json_bytes(record) for record in records)
        compressed = gzip.compress(uncompressed, mtime=0)
        path = catalog / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(compressed)
        entries.append(
            {
                "path": relative,
                "records": len(records),
                "sha256": hashlib.sha256(compressed).hexdigest(),
                "bytes": len(compressed),
                "uncompressed_bytes": len(uncompressed),
            }
        )
        total += len(records)
    inventory_digest = hashlib.sha256(
        canonical_json_bytes([{"path": entry["path"], "sha256": entry["sha256"]} for entry in entries])
    ).hexdigest()
    manifest: dict[str, object] = {
        "schema_version": 2,
        "catalog_updated_at": "2026-08-26T12:00:00Z",
        "totals": {"catalog_records": total, "shards": len(entries)},
        "shard_set_sha256": inventory_digest,
        "shard_manifest": entries,
    }
    catalog.mkdir(parents=True, exist_ok=True)
    (catalog / "manifest.json").write_bytes(canonical_json_bytes(manifest))
    return catalog, manifest


def rewrite_manifest(catalog: Path, manifest: dict[str, object]) -> None:
    inventory = manifest["shard_manifest"]
    assert isinstance(inventory, list)
    manifest["shard_set_sha256"] = hashlib.sha256(
        canonical_json_bytes([{"path": entry["path"], "sha256": entry["sha256"]} for entry in inventory])
    ).hexdigest()
    (catalog / "manifest.json").write_bytes(canonical_json_bytes(manifest))


class CVESearchDatabaseTests(unittest.TestCase):
    def test_builds_fts_content_filter_indexes_and_input_metadata(self) -> None:
        affected = cve_record(
            "CVE-2024-1001",
            title="Acme Secure Gateway validation flaw",
            summary="A parser accepts malformed gateway requests.",
            published="2024-05-01",
            affected_data=[
                {"vendor": "Acme Corporation", "product": "Secure Gateway"},
                {"vendor": "unknown", "product": "n/a"},
            ],
            products=[
                {"vendor": "Example Vendor", "product": "Widget Agent"},
                {"vendor": "*", "product": "-"},
            ],
        )
        newest_kev = cve_record(
            "CVE-2025-2001",
            title="Contoso Controller remote execution",
            summary="A network request can reach a vulnerable controller endpoint.",
            severity="critical",
            score=9.8,
            published="2025-09-10",
            kev=True,
            ecosystem="network/appliance",
            affected_data=[{"vendor": "Contoso", "product": "Edge Controller"}],
            recipe_kind="markdown-override",
            markdown=[
                {
                    "cve": "CVE-2025-2001",
                    "maturity": "stable",
                    "content_markdown": "Reviewed remediation guidance.",
                }
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog, manifest = write_catalog(
                root,
                {
                    "shards/2024/0001.jsonl.gz": [affected],
                    "shards/2025/0002.jsonl.gz": [newest_kev],
                },
            )
            output = root / "runtime-search.sqlite3"
            metadata_output = root / "runtime-search.sqlite3.metadata.json"
            result = search_db.build_search_database(
                catalog,
                output,
                metadata_path=metadata_output,
            )

            with closing(sqlite3.connect(output)) as connection:
                metadata = dict(connection.execute("SELECT key, value FROM metadata"))
                product_text = connection.execute("SELECT products FROM cves WHERE cve = 'CVE-2024-1001'").fetchone()[0]
                product_matches = [
                    row[0]
                    for row in connection.execute(
                        "SELECT cve FROM cve_fts WHERE cve_fts MATCH ? ORDER BY cve",
                        ('products:"secure gateway" OR products:"widget agent"',),
                    )
                ]
                newest = [
                    row[0] for row in connection.execute("SELECT cve FROM cves ORDER BY published DESC, cve DESC")
                ]
                filtered = [
                    row[0]
                    for row in connection.execute(
                        "SELECT cve FROM cves "
                        "WHERE severity = 'critical' AND publication_year = 2025 AND kev = 1 "
                        "ORDER BY published DESC, cve DESC"
                    )
                ]
                indexes = {row[1] for row in connection.execute("PRAGMA index_list('cves')")}
                fts_count = connection.execute("SELECT count(*) FROM cve_fts").fetchone()[0]
                integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
                markdown_flags = dict(connection.execute("SELECT cve, has_markdown FROM cves ORDER BY cve"))

            manifest_payload = (catalog / "manifest.json").read_bytes()
            self.assertEqual(result["records"], 2)
            self.assertEqual(result["shards"], 2)
            self.assertGreater(result["bytes"], 0)
            self.assertEqual(
                result["database_sha256"],
                hashlib.sha256(output.read_bytes()).hexdigest(),
            )
            self.assertEqual(
                json.loads(metadata_output.read_text(encoding="utf-8")),
                result,
            )
            self.assertEqual(metadata["database_schema_version"], "1")
            self.assertEqual(metadata["manifest_schema_version"], "2")
            self.assertEqual(metadata["record_count"], "2")
            self.assertEqual(metadata["shard_count"], "2")
            self.assertEqual(metadata["manifest_sha256"], hashlib.sha256(manifest_payload).hexdigest())
            self.assertEqual(metadata["shard_set_sha256"], manifest["shard_set_sha256"])
            self.assertIn("Acme Corporation Secure Gateway", product_text)
            self.assertIn("Example Vendor Widget Agent", product_text)
            self.assertNotIn("unknown", product_text.casefold())
            self.assertNotIn("n/a", product_text.casefold())
            self.assertNotIn("*", product_text)
            self.assertEqual(product_matches, ["CVE-2024-1001"])
            self.assertEqual(newest, ["CVE-2025-2001", "CVE-2024-1001"])
            self.assertEqual(filtered, ["CVE-2025-2001"])
            self.assertEqual(fts_count, 2)
            self.assertEqual(integrity, "ok")
            self.assertEqual(
                markdown_flags,
                {"CVE-2024-1001": 0, "CVE-2025-2001": 1},
            )
            self.assertTrue(
                {
                    "cves_newest_idx",
                    "cves_severity_newest_idx",
                    "cves_year_newest_idx",
                    "cves_kev_newest_idx",
                    "cves_filter_newest_idx",
                }.issubset(indexes)
            )
            self.assertFalse(Path(f"{output}-journal").exists())
            with self.assertRaisesRegex(
                search_db.SearchDatabaseBuildError,
                "output path cannot be inside the source catalog",
            ):
                search_db.build_search_database(
                    catalog,
                    catalog / "runtime-search.sqlite3",
                )
            with self.assertRaisesRegex(
                search_db.SearchDatabaseBuildError,
                "metadata output must differ",
            ):
                search_db.build_search_database(
                    catalog,
                    output,
                    metadata_path=output,
                )
            with self.assertRaisesRegex(
                search_db.SearchDatabaseBuildError,
                "metadata output cannot be inside the source catalog",
            ):
                search_db.build_search_database(
                    catalog,
                    output,
                    metadata_path=catalog / "runtime-search.metadata.json",
                )

    def test_integrity_and_record_shape_mismatches_fail_closed(self) -> None:
        base = cve_record(
            "CVE-2024-1001",
            title="Acme Gateway flaw",
            summary="A bounded test record.",
        )
        cases = (
            "manifest_schema",
            "compressed_bytes",
            "compressed_hash",
            "uncompressed_bytes",
            "record_count",
            "unsafe_path",
            "record_shape",
            "markdown_metadata",
            "duplicate",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                records = [deepcopy(base)]
                if case == "record_shape":
                    records[0].pop("summary")
                if case == "markdown_metadata":
                    records[0]["recipe_kind"] = "markdown-override"
                    records[0]["markdown"] = [
                        {
                            "cve": records[0]["cve"],
                            "maturity": "stable",
                        }
                    ]
                if case == "duplicate":
                    records.append(deepcopy(records[0]))
                catalog, manifest = write_catalog(
                    root,
                    {"shards/2024/0001.jsonl.gz": records},
                )
                entry = manifest["shard_manifest"][0]
                assert isinstance(entry, dict)
                if case == "manifest_schema":
                    manifest["schema_version"] = 3
                    rewrite_manifest(catalog, manifest)
                elif case == "compressed_bytes":
                    entry["bytes"] = int(entry["bytes"]) + 1
                    rewrite_manifest(catalog, manifest)
                elif case == "compressed_hash":
                    shard = catalog / str(entry["path"])
                    payload = bytearray(shard.read_bytes())
                    payload[-1] ^= 0x01
                    shard.write_bytes(payload)
                elif case == "uncompressed_bytes":
                    entry["uncompressed_bytes"] = int(entry["uncompressed_bytes"]) + 1
                    rewrite_manifest(catalog, manifest)
                elif case == "record_count":
                    entry["records"] = int(entry["records"]) + 1
                    totals = manifest["totals"]
                    assert isinstance(totals, dict)
                    totals["catalog_records"] = int(totals["catalog_records"]) + 1
                    rewrite_manifest(catalog, manifest)
                elif case == "unsafe_path":
                    entry["path"] = "../shards/2024/0001.jsonl.gz"
                    rewrite_manifest(catalog, manifest)

                with self.assertRaises(search_db.SearchDatabaseBuildError):
                    search_db.build_search_database(
                        catalog,
                        root / "runtime-search.sqlite3",
                    )

    def test_failed_rebuild_atomically_preserves_existing_database(self) -> None:
        source = cve_record(
            "CVE-2024-1001",
            title="Acme Gateway flaw",
            summary="A bounded test record.",
        )
        later_source = cve_record(
            "CVE-2025-2001",
            title="Contoso Controller flaw",
            summary="A second bounded test record.",
            published="2025-02-03",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog, manifest = write_catalog(
                root,
                {
                    "shards/2024/0001.jsonl.gz": [source],
                    "shards/2025/0002.jsonl.gz": [later_source],
                },
            )
            output = root / "runtime-search.sqlite3"
            search_db.build_search_database(catalog, output)
            before = output.read_bytes()

            entry = manifest["shard_manifest"][1]
            assert isinstance(entry, dict)
            shard = catalog / str(entry["path"])
            corrupted = bytearray(shard.read_bytes())
            corrupted[10] ^= 0x01
            shard.write_bytes(corrupted)

            with self.assertRaisesRegex(
                search_db.SearchDatabaseBuildError,
                "compressed hash mismatch",
            ):
                search_db.build_search_database(catalog, output)

            self.assertEqual(output.read_bytes(), before)
            self.assertEqual(list(root.glob(f".{output.name}.*.tmp")), [])
            with closing(sqlite3.connect(output)) as connection:
                self.assertEqual(
                    list(connection.execute("SELECT cve FROM cves ORDER BY cve")),
                    [("CVE-2024-1001",), ("CVE-2025-2001",)],
                )

    def test_repeated_builds_have_identical_logical_contents(self) -> None:
        records = [
            cve_record(
                "CVE-2024-1001",
                title="Acme Gateway flaw",
                summary="A bounded test record.",
            ),
            cve_record(
                "CVE-2024-1002",
                title="Acme Controller flaw",
                summary="Another bounded test record.",
                severity="medium",
                score=6.1,
            ),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog, _ = write_catalog(
                root,
                {"shards/2024/0001.jsonl.gz": records},
            )
            outputs = [root / "first.sqlite3", root / "second.sqlite3"]
            for output in outputs:
                search_db.build_search_database(catalog, output)

            snapshots = []
            for output in outputs:
                with closing(sqlite3.connect(output)) as connection:
                    snapshots.append(
                        {
                            "metadata": list(connection.execute("SELECT key, value FROM metadata ORDER BY key")),
                            "cves": list(
                                connection.execute(
                                    "SELECT cve, title, severity, published, kev, has_markdown FROM cves ORDER BY id"
                                )
                            ),
                            "fts": list(
                                connection.execute("SELECT rowid, cve, title, products FROM cve_fts ORDER BY rowid")
                            ),
                        }
                    )
            self.assertEqual(snapshots[0], snapshots[1])


if __name__ == "__main__":
    unittest.main()
