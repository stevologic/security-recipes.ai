from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import cve_catalog_release as release


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def write_catalog(root: Path, label: str) -> Path:
    catalog = root / "catalog"
    if catalog.exists():
        shutil.rmtree(catalog)
    shard_relative = "shards/2026/0001.jsonl.gz"
    record = {
        "cve": "CVE-2026-1000",
        "summary": f"{label} catalog record",
        "title": f"Release {label}",
        "severity": "medium",
        "score": 5.0,
        "published": "2026-08-01",
        "ecosystem": "general",
        "kev": False,
        "archetype": "generic",
        "archetypes": ["generic"],
        "recipe_kind": "composed",
        "cwes": [],
        "products": [],
    }
    compact_record = {
        "cve": record["cve"],
        "title": record["title"],
        "severity": record["severity"],
        "score": record["score"],
        "published": record["published"],
        "ecosystem": record["ecosystem"],
        "kev": record["kev"],
        "archetype": record["archetype"],
        "archetypes": record["archetypes"],
        "has_markdown": False,
        "shard": shard_relative,
    }
    uncompressed = canonical_json_bytes(record)
    compressed = gzip.compress(uncompressed, mtime=0)
    shard_path = catalog / shard_relative
    shard_path.parent.mkdir(parents=True, exist_ok=True)
    shard_path.write_bytes(compressed)
    shard_digest = hashlib.sha256(compressed).hexdigest()
    inventory = [
        {
            "path": shard_relative,
            "records": 1,
            "sha256": shard_digest,
            "bytes": len(compressed),
            "uncompressed_bytes": len(uncompressed),
        }
    ]
    shard_set = hashlib.sha256(
        canonical_json_bytes([{"path": shard_relative, "sha256": shard_digest}])
    ).hexdigest()
    catalog_updated_at = "2026-08-26T12:00:00Z"
    scope = {"published_start": "2026-01-01", "published_end": "2026-12-31"}

    archetypes_payload = canonical_json_bytes({"schema_version": 1, "label": label})
    (catalog / "archetypes.json").write_bytes(archetypes_payload)
    browser_uncompressed = canonical_json_bytes(
        {
            "schema_version": 2,
            "archetypes": ["generic"],
            "ecosystems": ["general"],
            "fields": [
                "cve",
                "title",
                "severity",
                "score",
                "published",
                "ecosystem_index",
                "kev",
                "archetype_indexes",
                "has_markdown",
            ],
            "records": [
                [
                    record["cve"],
                    record["title"],
                    0,
                    record["score"],
                    record["published"],
                    0,
                    False,
                    [0],
                    False,
                ]
            ],
            "severity_codes": {"0": "medium", "1": "high", "2": "critical"},
        }
    )
    browser_payload = gzip.compress(browser_uncompressed, mtime=0)
    (catalog / "browser-index.json.gz").write_bytes(browser_payload)
    runtime_payload = canonical_json_bytes({"schema_version": 2, "label": label})
    (catalog / "runtime-summary.json").write_bytes(runtime_payload)
    search_payload = canonical_json_bytes(
        {
            "schema_version": 2,
            "catalog_updated_at": catalog_updated_at,
            "policy": "fixture-policy",
            "records": [],
        }
    )
    (catalog / "search-indexable.json").write_bytes(search_payload)
    partition_uncompressed = canonical_json_bytes(
        {
            "schema_version": 2,
            "catalog_updated_at": catalog_updated_at,
            "year": "2026",
            "total": 1,
            "records": [compact_record],
        }
    )
    partition_payload = gzip.compress(partition_uncompressed, mtime=0)
    partition_path = catalog / "indexes/2026.json.gz"
    partition_path.parent.mkdir(parents=True, exist_ok=True)
    partition_path.write_bytes(partition_payload)
    partition = {
        "bytes": len(partition_payload),
        "path": "indexes/2026.json.gz",
        "records": 1,
        "sha256": hashlib.sha256(partition_payload).hexdigest(),
        "uncompressed_bytes": len(partition_uncompressed),
        "year": "2026",
    }
    index_payload = canonical_json_bytes(
        {
            "schema_version": 2,
            "catalog_updated_at": catalog_updated_at,
            "partition_key": "published_year",
            "partitions": [partition],
            "scope": scope,
            "total": 1,
        }
    )
    (catalog / "index.json").write_bytes(index_payload)
    manifest = {
        "schema_version": 2,
        "catalog_updated_at": catalog_updated_at,
        "scope": scope,
        "totals": {"catalog_records": 1, "shards": 1},
        "shard_set_sha256": shard_set,
        "shard_manifest": inventory,
        "archetypes_asset": {
            "path": "archetypes.json",
            "bytes": len(archetypes_payload),
            "sha256": hashlib.sha256(archetypes_payload).hexdigest(),
        },
        "browser_index": {
            "path": "browser-index.json.gz",
            "bytes": len(browser_payload),
            "uncompressed_bytes": len(browser_uncompressed),
            "records": 1,
            "sha256": hashlib.sha256(browser_payload).hexdigest(),
        },
        "runtime_summary": {
            "path": "runtime-summary.json",
            "bytes": len(runtime_payload),
            "sha256": hashlib.sha256(runtime_payload).hexdigest(),
        },
        "search_index": {
            "path": "search-indexable.json",
            "bytes": len(search_payload),
            "records": 0,
            "schema_version": 2,
            "policy": "fixture-policy",
            "sha256": hashlib.sha256(search_payload).hexdigest(),
        },
        "complete_index": {
            "format": "published-year-partitions",
            "path": "index.json",
            "records": 1,
            "partitions": [partition],
        },
    }
    (catalog / "manifest.json").write_bytes(canonical_json_bytes(manifest))
    return catalog


def snapshot(directory: Path) -> dict[str, bytes]:
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def write_tar_blob(path: Path, members: list[tuple[str, bytes]]) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                for name, payload in members:
                    member = tarfile.TarInfo(name)
                    member.size = len(payload)
                    member.mode = 0o644
                    member.mtime = 0
                    member.uid = 0
                    member.gid = 0
                    archive.addfile(member, fileobj=io.BytesIO(payload))


def descriptor_for_blob(base_descriptor: Path, blob: Path, destination: Path) -> Path:
    descriptor = json.loads(base_descriptor.read_text(encoding="utf-8"))
    payload = blob.read_bytes()
    descriptor["blob_sha256"] = hashlib.sha256(payload).hexdigest()
    descriptor["blob_size"] = len(payload)
    destination.write_bytes(canonical_json_bytes(descriptor))
    return destination


def descriptor_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rewrite_catalog_shard(
    catalog: Path,
    uncompressed: bytes,
    *,
    declared_records: int | None = None,
    declared_uncompressed_bytes: int | None = None,
) -> None:
    shard_relative = "shards/2026/0001.jsonl.gz"
    compressed = gzip.compress(uncompressed, mtime=0)
    (catalog / shard_relative).write_bytes(compressed)
    manifest = json.loads((catalog / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["shard_manifest"][0]
    entry["sha256"] = hashlib.sha256(compressed).hexdigest()
    entry["bytes"] = len(compressed)
    entry["uncompressed_bytes"] = (
        len(uncompressed) if declared_uncompressed_bytes is None else declared_uncompressed_bytes
    )
    entry["records"] = 1 if declared_records is None else declared_records
    manifest["totals"]["catalog_records"] = entry["records"]
    manifest["shard_set_sha256"] = hashlib.sha256(
        canonical_json_bytes([{"path": shard_relative, "sha256": entry["sha256"]}])
    ).hexdigest()
    (catalog / "manifest.json").write_bytes(canonical_json_bytes(manifest))


def descriptor_for_catalog_blob(
    base_descriptor: Path,
    catalog: Path,
    blob: Path,
    destination: Path,
) -> Path:
    descriptor = json.loads(base_descriptor.read_text(encoding="utf-8"))
    manifest_payload = (catalog / "manifest.json").read_bytes()
    manifest = json.loads(manifest_payload)
    blob_payload = blob.read_bytes()
    descriptor["record_count"] = manifest["totals"]["catalog_records"]
    descriptor["shard_set_sha256"] = manifest["shard_set_sha256"]
    descriptor["manifest_sha256"] = hashlib.sha256(manifest_payload).hexdigest()
    descriptor["blob_sha256"] = hashlib.sha256(blob_payload).hexdigest()
    descriptor["blob_size"] = len(blob_payload)
    destination.write_bytes(canonical_json_bytes(descriptor))
    return destination


def write_special_tar_header_blob(path: Path, member_type: bytes) -> None:
    member = tarfile.TarInfo("metadata-bomb")
    member.type = member_type
    member.size = release.MAX_ARCHIVE_UNCOMPRESSED_BYTES + 1
    header = member.tobuf(
        format=tarfile.USTAR_FORMAT,
        encoding="utf-8",
        errors="strict",
    )
    path.write_bytes(gzip.compress(header + (b"\0" * 1024), mtime=0))


def create_directory_link(link: Path, target: Path) -> None:
    if os.name == "nt":
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise unittest.SkipTest(f"junction creation unavailable: {completed.stderr.strip()}")
    else:
        os.symlink(target, link, target_is_directory=True)


def remove_directory_link(link: Path) -> None:
    if os.name == "nt":
        os.rmdir(link)
    else:
        link.unlink()


class CVECatalogReleaseTests(unittest.TestCase):
    def test_package_is_deterministic_content_addressed_and_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            first = release.package_catalog(catalog, root / "release-one")
            second = release.package_catalog(catalog, root / "release-two")

            self.assertEqual(first.descriptor_sha256, second.descriptor_sha256)
            self.assertEqual(first.blob_sha256, second.blob_sha256)
            self.assertEqual(first.blob_size, second.blob_size)
            self.assertEqual(first.descriptor_path.read_bytes(), second.descriptor_path.read_bytes())
            self.assertEqual(first.blob_path.read_bytes(), second.blob_path.read_bytes())
            self.assertEqual(first.blob_path.name, first.blob_sha256)
            self.assertEqual(first.descriptor_path.stem, first.descriptor_sha256)

            descriptor, digest = release.load_descriptor(first.descriptor_path)
            identity = release.validate_release(
                first.descriptor_path,
                first.blob_path,
                expected_descriptor_sha256=first.descriptor_sha256,
            )
            self.assertEqual(digest, first.descriptor_sha256)
            self.assertEqual(descriptor["schema"], release.RELEASE_SCHEMA)
            self.assertEqual(descriptor["record_count"], 1)
            self.assertEqual(descriptor["previous_release_sha256"], None)
            self.assertEqual(identity.record_count, 1)
            self.assertEqual(identity.shard_set_sha256, descriptor["shard_set_sha256"])

    def test_corrupt_blob_is_rejected_without_touching_existing_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            result = release.package_catalog(write_catalog(root, "A"), root / "release")
            corrupt_blob = root / "corrupt.tar.gz"
            payload = bytearray(result.blob_path.read_bytes())
            payload[len(payload) // 2] ^= 0xFF
            corrupt_blob.write_bytes(payload)
            target = root / "active"
            target.mkdir()
            (target / "sentinel.txt").write_text("old catalog\n", encoding="utf-8")
            before = snapshot(target)

            with self.assertRaisesRegex(release.CatalogReleaseError, "SHA-256"):
                release.hydrate_release(
                    result.descriptor_path,
                    corrupt_blob,
                    target,
                    expected_descriptor_sha256=result.descriptor_sha256,
                )

            self.assertEqual(snapshot(target), before)
            self.assertEqual(list(root.glob(".active.hydrate-*")), [])
            self.assertEqual(list(root.glob(".active.previous-*")), [])

    def test_traversal_member_is_rejected_without_writing_outside_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            result = release.package_catalog(catalog, root / "release")
            malicious_blob = root / "traversal.tar.gz"
            members = [(path.relative_to(catalog).as_posix(), path.read_bytes()) for path in catalog.rglob("*") if path.is_file()]
            members.append(("../escaped.txt", b"escaped\n"))
            write_tar_blob(malicious_blob, members)
            malicious_descriptor = descriptor_for_blob(
                result.descriptor_path,
                malicious_blob,
                root / "traversal-descriptor.json",
            )
            malicious_digest = hashlib.sha256(malicious_descriptor.read_bytes()).hexdigest()
            target = root / "active"
            target.mkdir()
            (target / "sentinel.txt").write_text("old catalog\n", encoding="utf-8")
            before = snapshot(target)

            with self.assertRaisesRegex(release.CatalogReleaseError, "unsafe archive member path"):
                release.hydrate_release(
                    malicious_descriptor,
                    malicious_blob,
                    target,
                    expected_descriptor_sha256=malicious_digest,
                )

            self.assertEqual(snapshot(target), before)
            self.assertFalse((root / "escaped.txt").exists())

    def test_partial_bundle_missing_a_manifest_shard_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            result = release.package_catalog(catalog, root / "release")
            partial_blob = root / "partial.tar.gz"
            write_tar_blob(partial_blob, [("manifest.json", (catalog / "manifest.json").read_bytes())])
            partial_descriptor = descriptor_for_blob(
                result.descriptor_path,
                partial_blob,
                root / "partial-descriptor.json",
            )
            partial_digest = hashlib.sha256(partial_descriptor.read_bytes()).hexdigest()
            target = root / "active"
            target.mkdir()
            (target / "sentinel.txt").write_text("old catalog\n", encoding="utf-8")
            before = snapshot(target)

            with self.assertRaisesRegex(release.CatalogReleaseError, "missing or unvalidated"):
                release.hydrate_release(
                    partial_descriptor,
                    partial_blob,
                    target,
                    expected_descriptor_sha256=partial_digest,
                )

            self.assertEqual(snapshot(target), before)

    def test_commit_failure_restores_previous_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            result = release.package_catalog(write_catalog(root, "A"), root / "release")
            target = root / "active"
            target.mkdir()
            (target / "sentinel.txt").write_text("old catalog\n", encoding="utf-8")
            before = snapshot(target)
            real_replace = os.replace
            failed = False

            def fail_staging_commit(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
                nonlocal failed
                source_path = Path(source)
                destination_path = Path(destination)
                if (
                    not failed
                    and destination_path == target
                    and source_path.name.startswith(".active.hydrate-")
                ):
                    failed = True
                    raise OSError("simulated final rename failure")
                real_replace(source, destination)

            with mock.patch.object(release.os, "replace", side_effect=fail_staging_commit):
                with self.assertRaisesRegex(release.CatalogReleaseError, "cannot commit"):
                    release.hydrate_release(
                        result.descriptor_path,
                        result.blob_path,
                        target,
                        expected_descriptor_sha256=result.descriptor_sha256,
                    )

            self.assertTrue(failed)
            self.assertEqual(snapshot(target), before)
            self.assertEqual(list(root.glob(".active.hydrate-*")), [])
            self.assertEqual(list(root.glob(".active.previous-*")), [])

    def test_committed_journal_write_failure_returns_committed_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            store = root / "release"
            release_a = release.package_catalog(write_catalog(root, "A"), store)
            target = root / "active"
            release.hydrate_release(
                release_a.descriptor_path,
                release_a.blob_path,
                target,
                expected_descriptor_sha256=release_a.descriptor_sha256,
            )
            release_b = release.package_catalog(
                write_catalog(root, "B"),
                store,
                previous_release_sha256=release_a.descriptor_sha256,
            )
            real_write_journal = release._write_journal

            def fail_committed_journal(
                journal_target: Path,
                *,
                staging: Path,
                backup: Path | None,
                descriptor_digest: str,
                phase: str,
            ) -> None:
                if phase == "committed":
                    raise release.CatalogReleaseError("simulated committed journal failure")
                real_write_journal(
                    journal_target,
                    staging=staging,
                    backup=backup,
                    descriptor_digest=descriptor_digest,
                    phase=phase,
                )

            with mock.patch.object(
                release,
                "_write_journal",
                side_effect=fail_committed_journal,
            ):
                validated = release.hydrate_release(
                    release_b.descriptor_path,
                    release_b.blob_path,
                    target,
                    expected_descriptor_sha256=release_b.descriptor_sha256,
                )

            self.assertEqual(validated.descriptor_sha256, release_b.descriptor_sha256)
            self.assertEqual(json.loads((target / "runtime-summary.json").read_text())["label"], "B")
            self.assertEqual(list(root.glob(".active.previous-*")), [])
            self.assertFalse(release._journal_file(target).exists())

    def test_immutable_releases_support_a_to_b_to_a_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            store = root / "release-store"
            catalog = write_catalog(root, "A")
            release_a = release.package_catalog(catalog, store)
            target = root / "active"
            release.hydrate_release(
                release_a.descriptor_path,
                release_a.blob_path,
                target,
                expected_descriptor_sha256=release_a.descriptor_sha256,
            )
            snapshot_a = snapshot(target)

            catalog = write_catalog(root, "B")
            release_b = release.package_catalog(
                catalog,
                store,
                previous_release_sha256=release_a.descriptor_sha256,
            )
            descriptor_b, _ = release.load_descriptor(release_b.descriptor_path)
            self.assertEqual(descriptor_b["previous_release_sha256"], release_a.descriptor_sha256)
            self.assertNotEqual(release_b.descriptor_sha256, release_a.descriptor_sha256)
            self.assertNotEqual(release_b.blob_sha256, release_a.blob_sha256)

            release.hydrate_release(
                release_b.descriptor_path,
                release_b.blob_path,
                target,
                expected_descriptor_sha256=release_b.descriptor_sha256,
            )
            snapshot_b = snapshot(target)
            self.assertNotEqual(snapshot_b, snapshot_a)
            self.assertEqual(json.loads((target / "runtime-summary.json").read_text())["label"], "B")

            release.hydrate_release(
                release_a.descriptor_path,
                release_a.blob_path,
                target,
                expected_descriptor_sha256=release_a.descriptor_sha256,
            )
            self.assertEqual(snapshot(target), snapshot_a)
            self.assertEqual(json.loads((target / "runtime-summary.json").read_text())["label"], "A")

    def test_expected_descriptor_digest_is_a_required_trust_anchor_and_is_returned(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            result = release.package_catalog(write_catalog(root, "A"), root / "release")

            with self.assertRaisesRegex(release.CatalogReleaseError, "expected digest"):
                release.validate_release(
                    result.descriptor_path,
                    result.blob_path,
                    expected_descriptor_sha256="0" * 64,
                )
            with self.assertRaisesRegex(release.CatalogReleaseError, "lowercase SHA-256"):
                release.validate_release(
                    result.descriptor_path,
                    result.blob_path,
                    expected_descriptor_sha256=None,  # type: ignore[arg-type]
                )
            with self.assertRaisesRegex(release.CatalogReleaseError, "lowercase SHA-256"):
                release.hydrate_release(
                    result.descriptor_path,
                    result.blob_path,
                    root / "unapproved-target",
                    expected_descriptor_sha256=None,  # type: ignore[arg-type]
                )
            self.assertFalse((root / "unapproved-target").exists())
            validated = release.validate_release(
                result.descriptor_path,
                result.blob_path,
                expected_descriptor_sha256=result.descriptor_sha256,
            )
            self.assertEqual(validated.descriptor_sha256, result.descriptor_sha256)

    def test_package_rejects_output_root_and_store_namespace_reparse_points(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            outside = root / "outside"
            outside.mkdir()
            linked_output = root / "linked-output"
            create_directory_link(linked_output, outside)
            try:
                with self.assertRaisesRegex(release.CatalogReleaseError, "link|reparse"):
                    release.package_catalog(catalog, linked_output)
                self.assertEqual(list(outside.iterdir()), [])
            finally:
                remove_directory_link(linked_output)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            output = root / "release"
            output.mkdir()
            outside = root / "outside"
            outside.mkdir()
            linked_namespace = output / "releases"
            create_directory_link(linked_namespace, outside)
            try:
                with self.assertRaisesRegex(release.CatalogReleaseError, "link|reparse"):
                    release.package_catalog(catalog, output)
                self.assertEqual(list(outside.iterdir()), [])
            finally:
                remove_directory_link(linked_namespace)

    def test_package_rejects_release_store_swap_before_immutable_install(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            output = root / "release"
            blob_store = output / "blobs" / "sha256"
            displaced_store = root / "displaced-blob-store"
            outside = root / "outside"
            outside.mkdir()
            real_validate = release._validate_blob
            swapped = False

            def validate_then_swap(*args: object, **kwargs: object) -> release.ValidatedRelease:
                nonlocal swapped
                validated = real_validate(*args, **kwargs)
                if not swapped:
                    os.replace(blob_store, displaced_store)
                    create_directory_link(blob_store, outside)
                    swapped = True
                return validated

            try:
                with mock.patch.object(
                    release,
                    "_validate_blob",
                    side_effect=validate_then_swap,
                ):
                    with self.assertRaisesRegex(
                        release.CatalogReleaseError,
                        "link|reparse|changed",
                    ):
                        release.package_catalog(catalog, output)
                self.assertEqual(list(outside.iterdir()), [])
            finally:
                if os.path.lexists(blob_store) and release._is_link_or_junction(blob_store):
                    remove_directory_link(blob_store)

    def test_descriptor_integer_fields_reject_booleans(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            result = release.package_catalog(write_catalog(root, "A"), root / "release")
            original = json.loads(result.descriptor_path.read_text(encoding="utf-8"))
            for field in ("schema_version", "record_count", "blob_size"):
                with self.subTest(field=field):
                    altered = dict(original)
                    altered[field] = True
                    path = root / f"bool-{field}.json"
                    path.write_bytes(canonical_json_bytes(altered))
                    with self.assertRaises(release.CatalogReleaseError):
                        release.load_descriptor(
                            path,
                            expected_descriptor_sha256=descriptor_digest(path),
                        )

    def test_outer_gzip_expansion_is_bounded_before_tar_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            result = release.package_catalog(write_catalog(root, "A"), root / "release")
            with mock.patch.object(release, "MAX_ARCHIVE_UNCOMPRESSED_BYTES", 1024):
                with self.assertRaisesRegex(release.CatalogReleaseError, "gzip expands"):
                    release.validate_release(
                        result.descriptor_path,
                        result.blob_path,
                        expected_descriptor_sha256=result.descriptor_sha256,
                    )

    def test_pax_gnu_longname_and_global_pax_metadata_bombs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            result = release.package_catalog(write_catalog(root, "A"), root / "release")
            member_types = {
                "pax": tarfile.XHDTYPE,
                "global-pax": tarfile.XGLTYPE,
                "gnu-longname": tarfile.GNUTYPE_LONGNAME,
            }
            for label, member_type in member_types.items():
                with self.subTest(member_type=label):
                    blob = root / f"{label}.tar.gz"
                    write_special_tar_header_blob(blob, member_type)
                    descriptor = descriptor_for_blob(
                        result.descriptor_path,
                        blob,
                        root / f"{label}-descriptor.json",
                    )
                    with self.assertRaisesRegex(
                        release.CatalogReleaseError,
                        "non-regular or metadata member type",
                    ):
                        release.validate_release(
                            descriptor,
                            blob,
                            expected_descriptor_sha256=descriptor_digest(descriptor),
                        )

    def test_tar_hardlink_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            result = release.package_catalog(write_catalog(root, "A"), root / "release")
            blob = root / "hardlink.tar.gz"
            write_special_tar_header_blob(blob, tarfile.LNKTYPE)
            descriptor = descriptor_for_blob(
                result.descriptor_path,
                blob,
                root / "hardlink-descriptor.json",
            )
            with self.assertRaisesRegex(release.CatalogReleaseError, "non-regular"):
                release.validate_release(
                    descriptor,
                    blob,
                    expected_descriptor_sha256=descriptor_digest(descriptor),
                )

    def test_all_windows_invalid_filename_characters_are_rejected(self) -> None:
        for character in '<>:"\\|?*':
            with self.subTest(character=character):
                with self.assertRaisesRegex(release.CatalogReleaseError, "unsafe archive member path"):
                    release._safe_member_path(f"bad{character}name.json")

    def test_reparse_attribute_fallback_detects_windows_reparse_points(self) -> None:
        fake = SimpleNamespace(
            st_mode=stat.S_IFDIR,
            st_file_attributes=release._REPARSE_ATTRIBUTE,
        )
        with mock.patch.object(release.os, "lstat", return_value=fake):
            self.assertTrue(release._is_link_or_junction(Path("synthetic-reparse")))

    @unittest.skipUnless(os.name == "nt", "Windows junction semantics")
    def test_real_windows_junction_catalog_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = write_catalog(root, "A")
            junction = root / "catalog-junction"
            completed = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(source)],
                capture_output=True,
                text=True,
                check=False,
            )
            if completed.returncode != 0:
                self.skipTest(f"junction creation unavailable: {completed.stderr.strip()}")
            try:
                self.assertTrue(release._is_link_or_junction(junction))
                with self.assertRaisesRegex(release.CatalogReleaseError, "reparse point"):
                    release.package_catalog(junction, root / "release")
            finally:
                os.rmdir(junction)

    def test_private_descriptor_hardlink_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            result = release.package_catalog(write_catalog(root, "A"), root / "release")
            linked = root / "linked-descriptor.json"
            try:
                os.link(result.descriptor_path, linked)
            except OSError as exc:
                self.skipTest(f"hardlinks unavailable: {exc}")
            with self.assertRaisesRegex(release.CatalogReleaseError, "private regular file"):
                release.validate_release(
                    linked,
                    result.blob_path,
                    expected_descriptor_sha256=result.descriptor_sha256,
                )

    def test_shard_gzip_body_and_canonical_cve_path_are_validated(self) -> None:
        invalid_payloads = {
            "wrong-path": canonical_json_bytes({"cve": "CVE-2025-1000"}),
            "non-object": canonical_json_bytes(["CVE-2026-1000"]),
            "invalid-cve": canonical_json_bytes({"cve": "cve-2026-1000"}),
            "unsorted": b"".join(
                [
                    canonical_json_bytes({"cve": "CVE-2026-1001"}),
                    canonical_json_bytes({"cve": "CVE-2026-1000"}),
                ]
            ),
        }
        for label, payload in invalid_payloads.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                catalog = write_catalog(root, "A")
                rewrite_catalog_shard(catalog, payload)
                with self.assertRaises(release.CatalogReleaseError):
                    release.package_catalog(catalog, root / "release")

    def test_archive_validation_rechecks_shard_body_not_only_manifest_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            result = release.package_catalog(catalog, root / "release")
            rewrite_catalog_shard(
                catalog,
                canonical_json_bytes({"cve": "CVE-2025-1000", "title": "wrong shard"}),
            )
            blob = root / "invalid-shard.tar.gz"
            members = [
                (path.relative_to(catalog).as_posix(), path.read_bytes())
                for path in catalog.rglob("*")
                if path.is_file()
            ]
            write_tar_blob(blob, members)
            descriptor = descriptor_for_catalog_blob(
                result.descriptor_path,
                catalog,
                blob,
                root / "invalid-shard-descriptor.json",
            )
            with self.assertRaisesRegex(release.CatalogReleaseError, "wrong shard"):
                release.validate_release(
                    descriptor,
                    blob,
                    expected_descriptor_sha256=descriptor_digest(descriptor),
                )

    def test_manifest_owns_exact_non_shard_asset_set_integrity_and_index_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            result = release.package_catalog(catalog, root / "release")
            original_members = {
                path.relative_to(catalog).as_posix(): path.read_bytes()
                for path in catalog.rglob("*")
                if path.is_file()
            }
            invalid_index = json.loads(original_members["index.json"])
            invalid_index["total"] = 2
            cases = {
                "missing": (
                    {path: payload for path, payload in original_members.items() if path != "runtime-summary.json"},
                    "missing or corrupt",
                ),
                "tampered": (
                    {**original_members, "runtime-summary.json": canonical_json_bytes({"tampered": True})},
                    "missing or corrupt",
                ),
                "extra": (
                    {**original_members, "undeclared.json": canonical_json_bytes({"extra": True})},
                    "physical file set",
                ),
                "index-contract": (
                    {**original_members, "index.json": canonical_json_bytes(invalid_index)},
                    "index.json does not match",
                ),
            }
            for label, (members, error) in cases.items():
                with self.subTest(label=label):
                    blob = root / f"{label}.tar.gz"
                    write_tar_blob(blob, list(members.items()))
                    descriptor = descriptor_for_blob(
                        result.descriptor_path,
                        blob,
                        root / f"{label}-descriptor.json",
                    )
                    with self.assertRaisesRegex(release.CatalogReleaseError, error):
                        release.validate_release(
                            descriptor,
                            blob,
                            expected_descriptor_sha256=descriptor_digest(descriptor),
                        )

    def test_projection_records_must_match_authoritative_shard_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            partition_path = catalog / "indexes/2026.json.gz"
            partition = json.loads(gzip.decompress(partition_path.read_bytes()))
            partition["records"][0]["title"] = "stale projection title"
            partition_uncompressed = canonical_json_bytes(partition)
            partition_payload = gzip.compress(partition_uncompressed, mtime=0)
            partition_path.write_bytes(partition_payload)

            manifest_path = catalog / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            metadata = manifest["complete_index"]["partitions"][0]
            metadata["bytes"] = len(partition_payload)
            metadata["uncompressed_bytes"] = len(partition_uncompressed)
            metadata["sha256"] = hashlib.sha256(partition_payload).hexdigest()
            manifest_path.write_bytes(canonical_json_bytes(manifest))

            index_path = catalog / "index.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["partitions"] = manifest["complete_index"]["partitions"]
            index_path.write_bytes(canonical_json_bytes(index))

            with self.assertRaisesRegex(
                release.CatalogReleaseError,
                "complete index projection disagrees",
            ):
                release.package_catalog(catalog, root / "release")

    def test_complete_index_record_must_use_its_published_year_partition(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            partition_path = catalog / "indexes/2026.json.gz"
            partition = json.loads(gzip.decompress(partition_path.read_bytes()))
            partition["records"][0]["published"] = "2025-12-31"
            partition_uncompressed = canonical_json_bytes(partition)
            partition_payload = gzip.compress(partition_uncompressed, mtime=0)
            partition_path.write_bytes(partition_payload)

            manifest_path = catalog / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            metadata = manifest["complete_index"]["partitions"][0]
            metadata["bytes"] = len(partition_payload)
            metadata["uncompressed_bytes"] = len(partition_uncompressed)
            metadata["sha256"] = hashlib.sha256(partition_payload).hexdigest()
            manifest_path.write_bytes(canonical_json_bytes(manifest))

            index_path = catalog / "index.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["partitions"] = manifest["complete_index"]["partitions"]
            index_path.write_bytes(canonical_json_bytes(index))

            with self.assertRaisesRegex(
                release.CatalogReleaseError,
                "wrong publication-year partition",
            ):
                release.package_catalog(catalog, root / "release")

    def test_projection_record_work_is_bounded_before_ledger_insertion(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            browser_path = catalog / "browser-index.json.gz"
            browser = json.loads(gzip.decompress(browser_path.read_bytes()))
            browser["records"].append(list(browser["records"][0]))
            browser_uncompressed = canonical_json_bytes(browser)
            browser_payload = gzip.compress(browser_uncompressed, mtime=0)
            browser_path.write_bytes(browser_payload)

            manifest_path = catalog / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            metadata = manifest["browser_index"]
            metadata["bytes"] = len(browser_payload)
            metadata["uncompressed_bytes"] = len(browser_uncompressed)
            metadata["records"] = 2
            metadata["sha256"] = hashlib.sha256(browser_payload).hexdigest()
            manifest_path.write_bytes(canonical_json_bytes(manifest))

            with self.assertRaisesRegex(
                release.CatalogReleaseError,
                "projection record count exceeds",
            ):
                release.package_catalog(catalog, root / "release")

    def test_actual_record_and_nested_gzip_aggregate_limits_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            result = release.package_catalog(catalog, root / "release")
            authoritative = json.loads(
                gzip.decompress((catalog / "shards/2026/0001.jsonl.gz").read_bytes())
            )
            authoritative["cve"] = "CVE-2026-2000"
            authoritative["title"] = "Unexpected second authoritative record"
            extra_shard = gzip.compress(canonical_json_bytes(authoritative), mtime=0)
            members = [
                (path.relative_to(catalog).as_posix(), path.read_bytes())
                for path in catalog.rglob("*")
                if path.is_file()
            ]
            members.append(("shards/2026/0002.jsonl.gz", extra_shard))
            blob = root / "too-many-records.tar.gz"
            write_tar_blob(blob, members)
            descriptor = descriptor_for_blob(
                result.descriptor_path,
                blob,
                root / "too-many-records-descriptor.json",
            )
            with self.assertRaisesRegex(release.CatalogReleaseError, "record count exceeds"):
                release.validate_release(
                    descriptor,
                    blob,
                    expected_descriptor_sha256=descriptor_digest(descriptor),
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            with mock.patch.object(release, "MAX_NESTED_UNCOMPRESSED_BYTES", 1):
                with self.assertRaisesRegex(release.CatalogReleaseError, "aggregate limit"):
                    release.package_catalog(catalog, root / "release")

    def test_manifest_record_and_expanded_byte_counts_must_match_shard_body(self) -> None:
        cases = {
            "records": {"declared_records": 2},
            "expanded": {"declared_uncompressed_bytes": 1},
        }
        for label, overrides in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                catalog = write_catalog(root, "A")
                record = gzip.decompress((catalog / "shards/2026/0001.jsonl.gz").read_bytes())
                rewrite_catalog_shard(catalog, record, **overrides)
                with self.assertRaisesRegex(release.CatalogReleaseError, "disagrees"):
                    release.package_catalog(catalog, root / "release")

    def test_shard_expansion_cap_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            with mock.patch.object(release, "MAX_SHARD_UNCOMPRESSED_BYTES", 8):
                with self.assertRaisesRegex(release.CatalogReleaseError, "bounds|expanded shard"):
                    release.package_catalog(catalog, root / "release")

    def test_shard_hash_truncation_and_json_line_caps_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            shard = catalog / "shards/2026/0001.jsonl.gz"
            shard.write_bytes(shard.read_bytes()[:-4])
            with self.assertRaises(release.CatalogReleaseError):
                release.package_catalog(catalog, root / "truncated-release")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            manifest = json.loads((catalog / "manifest.json").read_text(encoding="utf-8"))
            manifest["shard_manifest"][0]["sha256"] = "0" * 64
            manifest["shard_set_sha256"] = hashlib.sha256(
                canonical_json_bytes(
                    [
                        {
                            "path": manifest["shard_manifest"][0]["path"],
                            "sha256": "0" * 64,
                        }
                    ]
                )
            ).hexdigest()
            (catalog / "manifest.json").write_bytes(canonical_json_bytes(manifest))
            with self.assertRaisesRegex(release.CatalogReleaseError, "disagrees"):
                release.package_catalog(catalog, root / "hash-release")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            with mock.patch.object(release, "MAX_JSON_LINE_BYTES", 8):
                with self.assertRaisesRegex(release.CatalogReleaseError, "JSON line"):
                    release.package_catalog(catalog, root / "line-release")

    def test_package_detects_source_toctou_before_archive_visibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            shard = catalog / "shards/2026/0001.jsonl.gz"
            real_writer = release._write_deterministic_blob

            def mutate_then_write(files: list[release.CatalogFile], destination: Path) -> None:
                payload = bytearray(shard.read_bytes())
                payload[-1] ^= 0x01
                shard.write_bytes(payload)
                real_writer(files, destination)

            with mock.patch.object(
                release,
                "_write_deterministic_blob",
                side_effect=mutate_then_write,
            ):
                with self.assertRaisesRegex(release.CatalogReleaseError, "changed before"):
                    release.package_catalog(catalog, root / "release")
            self.assertEqual(list((root / "release" / "blobs" / "sha256").glob("[0-9a-f]*")), [])

    def test_package_member_and_aggregate_bounds_fail_before_archive_writer(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            catalog = write_catalog(root, "A")
            with (
                mock.patch.object(release, "MAX_ARCHIVE_MEMBERS", 1),
                mock.patch.object(release, "_write_deterministic_blob") as writer,
            ):
                with self.assertRaisesRegex(release.CatalogReleaseError, "too many files"):
                    release.package_catalog(catalog, root / "member-release")
                writer.assert_not_called()
            with (
                mock.patch.object(release, "MAX_ARCHIVE_UNCOMPRESSED_BYTES", 512),
                mock.patch.object(release, "_write_deterministic_blob") as writer,
            ):
                with self.assertRaisesRegex(release.CatalogReleaseError, "archive byte limit"):
                    release.package_catalog(catalog, root / "byte-release")
                writer.assert_not_called()

    def test_file_directory_collision_registration_is_linear_and_fail_closed(self) -> None:
        files: set[str] = set()
        directories: set[str] = set()
        release._register_archive_member(
            "Dir/File.json",
            portable_files=files,
            portable_directories=directories,
        )
        with self.assertRaisesRegex(release.CatalogReleaseError, "conflicts"):
            release._register_archive_member(
                "dir",
                portable_files=files,
                portable_directories=directories,
            )

    def test_exclusive_target_lock_rejects_a_concurrent_hydrator(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            result = release.package_catalog(write_catalog(root, "A"), root / "release")
            target = root / "active"
            with release._target_lock(target):
                with self.assertRaisesRegex(release.CatalogReleaseError, "already locked"):
                    release.hydrate_release(
                        result.descriptor_path,
                        result.blob_path,
                        target,
                        expected_descriptor_sha256=result.descriptor_sha256,
                    )

    def test_cleanup_failure_retains_backup_and_journal_then_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            store = root / "release"
            release_a = release.package_catalog(write_catalog(root, "A"), store)
            target = root / "active"
            release.hydrate_release(
                release_a.descriptor_path,
                release_a.blob_path,
                target,
                expected_descriptor_sha256=release_a.descriptor_sha256,
            )
            release_b = release.package_catalog(
                write_catalog(root, "B"),
                store,
                previous_release_sha256=release_a.descriptor_sha256,
            )
            real_remove = release._safe_remove_owned_tree

            def fail_backup_cleanup(path: Path, *, target: Path, kind: str) -> None:
                if kind == "backup":
                    raise release.CatalogReleaseError("simulated cleanup failure")
                real_remove(path, target=target, kind=kind)

            with mock.patch.object(release, "_safe_remove_owned_tree", side_effect=fail_backup_cleanup):
                validated = release.hydrate_release(
                    release_b.descriptor_path,
                    release_b.blob_path,
                    target,
                    expected_descriptor_sha256=release_b.descriptor_sha256,
                )

            self.assertIsNotNone(validated.retained_backup)
            self.assertTrue(validated.retained_backup.is_dir())
            self.assertTrue(release._journal_file(target).is_file())
            self.assertEqual(json.loads((target / "runtime-summary.json").read_text())["label"], "B")
            with release._target_lock(target):
                release._recover_hydration(target)
            self.assertFalse(validated.retained_backup.exists())
            self.assertFalse(release._journal_file(target).exists())

    def test_failed_restore_keeps_recovery_journal_and_next_recovery_restores_old_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            store = root / "release"
            release_a = release.package_catalog(write_catalog(root, "A"), store)
            target = root / "active"
            release.hydrate_release(
                release_a.descriptor_path,
                release_a.blob_path,
                target,
                expected_descriptor_sha256=release_a.descriptor_sha256,
            )
            before = snapshot(target)
            release_b = release.package_catalog(
                write_catalog(root, "B"),
                store,
                previous_release_sha256=release_a.descriptor_sha256,
            )
            real_replace = os.replace
            final_failed = False
            restore_failed = False

            def fail_commit_and_first_restore(
                source: str | os.PathLike[str],
                destination: str | os.PathLike[str],
            ) -> None:
                nonlocal final_failed, restore_failed
                source_path = Path(source)
                destination_path = Path(destination)
                if destination_path == target and source_path.name.startswith(".active.hydrate-"):
                    final_failed = True
                    raise OSError("simulated commit failure")
                if (
                    final_failed
                    and not restore_failed
                    and destination_path == target
                    and source_path.name.startswith(".active.previous-")
                ):
                    restore_failed = True
                    raise OSError("simulated restore failure")
                real_replace(source, destination)

            with mock.patch.object(release.os, "replace", side_effect=fail_commit_and_first_restore):
                with self.assertRaisesRegex(release.CatalogReleaseError, "automatic recovery also failed"):
                    release.hydrate_release(
                        release_b.descriptor_path,
                        release_b.blob_path,
                        target,
                        expected_descriptor_sha256=release_b.descriptor_sha256,
                    )

            self.assertTrue(final_failed)
            self.assertTrue(restore_failed)
            self.assertFalse(target.exists())
            self.assertTrue(release._journal_file(target).exists())
            with release._target_lock(target):
                release._recover_hydration(target)
            self.assertEqual(snapshot(target), before)
            self.assertFalse(release._journal_file(target).exists())

    def test_recovery_journal_handles_every_commit_phase(self) -> None:
        phases = ("prepared", "switching", "old_moved", "committed", "cleanup_pending")
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                target = root / "active"
                token = "a" * 32
                staging = root / f".active.hydrate-{token}"
                backup = root / f".active.previous-{token}"
                digest = "b" * 64

                if phase in {"prepared", "switching"}:
                    target.mkdir()
                    (target / "old.txt").write_text("old\n", encoding="utf-8")
                    staging.mkdir()
                    (staging / "partial.txt").write_text("partial\n", encoding="utf-8")
                elif phase == "old_moved":
                    backup.mkdir()
                    (backup / "old.txt").write_text("old\n", encoding="utf-8")
                    staging.mkdir()
                    (staging / "partial.txt").write_text("partial\n", encoding="utf-8")
                else:
                    target.mkdir()
                    (target / release.HYDRATED_MARKER).write_bytes(release._marker_payload(digest))
                    (target / "new.txt").write_text("new\n", encoding="utf-8")
                    backup.mkdir()
                    (backup / "old.txt").write_text("old\n", encoding="utf-8")

                journal_backup = backup if phase not in {"prepared", "switching"} else backup
                release._write_journal(
                    target,
                    staging=staging,
                    backup=journal_backup,
                    descriptor_digest=digest,
                    phase=phase,
                )
                with release._target_lock(target):
                    release._recover_hydration(target)

                self.assertFalse(staging.exists())
                self.assertFalse(backup.exists())
                self.assertFalse(release._journal_file(target).exists())
                if phase in {"prepared", "switching", "old_moved"}:
                    self.assertEqual((target / "old.txt").read_text(encoding="utf-8"), "old\n")
                else:
                    self.assertEqual((target / "new.txt").read_text(encoding="utf-8"), "new\n")


if __name__ == "__main__":
    unittest.main()
