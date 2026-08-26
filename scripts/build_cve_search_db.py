#!/usr/bin/env python3
"""Build the bounded SQLite/FTS5 search artifact for the CVE runtime catalog."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import os
import re
import sqlite3
import tempfile
from datetime import date, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "static" / "api" / "cve-catalog"
DEFAULT_OUTPUT = ROOT / "tmp" / "runtime-search.sqlite3"
DATABASE_SCHEMA_VERSION = 1
MANIFEST_SCHEMA_VERSION = 2
APPLICATION_ID = 0x43564553  # "CVES"

SHA256_RE = re.compile(r"[0-9a-f]{64}")
SHARD_PATH_RE = re.compile(r"shards/\d{4}/\d{4,}\.jsonl\.gz")
CVE_RE = re.compile(r"CVE-(\d{4})-(\d{4,})")
SEVERITY_RANK = {"medium": 1, "high": 2, "critical": 3}

MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_SHARDS = 100_000
MAX_CATALOG_RECORDS = 1_000_000
MAX_SHARD_COMPRESSED_BYTES = 8 * 1024 * 1024
MAX_SHARD_UNCOMPRESSED_BYTES = 32 * 1024 * 1024
MAX_JSON_LINE_BYTES = 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
INSERT_BATCH_SIZE = 1_000
MAX_TITLE_CHARS = 500
MAX_SUMMARY_CHARS = 4_000
MAX_ECOSYSTEM_CHARS = 300
MAX_ARCHETYPES = 64
MAX_ARCHETYPE_CHARS = 160
MAX_PRODUCT_ROWS = 128
MAX_PRODUCT_NAME_CHARS = 300
MAX_MARKDOWN_ROWS = 128

PLACEHOLDER_PRODUCT_NAMES = frozenset(
    {
        "",
        "*",
        "-",
        "?",
        "all",
        "any",
        "generic",
        "multiple",
        "n/a",
        "na",
        "none",
        "not applicable",
        "not available",
        "not specified",
        "null",
        "product",
        "unknown",
        "unspecified",
        "various",
        "vendor",
    }
)

CREATE_SCHEMA_SQL = """
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE cves (
    id INTEGER PRIMARY KEY,
    cve TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    archetypes TEXT NOT NULL,
    products TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('medium', 'high', 'critical')),
    severity_rank INTEGER NOT NULL CHECK (severity_rank BETWEEN 1 AND 3),
    score REAL NOT NULL CHECK (score >= 4.0 AND score <= 10.0),
    published TEXT NOT NULL,
    publication_year INTEGER NOT NULL,
    kev INTEGER NOT NULL CHECK (kev IN (0, 1)),
    has_markdown INTEGER NOT NULL CHECK (has_markdown IN (0, 1)),
    shard_path TEXT NOT NULL
);
"""

CREATE_INDEXES_SQL = """
CREATE INDEX cves_newest_idx
    ON cves(published DESC, cve DESC);
CREATE INDEX cves_severity_newest_idx
    ON cves(severity, published DESC, cve DESC);
CREATE INDEX cves_year_newest_idx
    ON cves(publication_year, published DESC, cve DESC);
CREATE INDEX cves_kev_newest_idx
    ON cves(kev, published DESC, cve DESC);
CREATE INDEX cves_filter_newest_idx
    ON cves(severity, publication_year, kev, published DESC, cve DESC);
"""

CREATE_FTS_SQL = """
CREATE VIRTUAL TABLE cve_fts USING fts5(
    cve,
    title,
    summary,
    ecosystem,
    archetypes,
    products,
    content='cves',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
"""

INSERT_CVE_SQL = """
INSERT INTO cves (
    cve, title, summary, ecosystem, archetypes, products,
    severity, severity_rank, score, published, publication_year, kev,
    has_markdown, shard_path
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class SearchDatabaseBuildError(ValueError):
    """The source catalog cannot safely produce a runtime search database."""


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction and is_junction())


def _reject_json_constant(value: str) -> None:
    raise SearchDatabaseBuildError(f"non-finite JSON value is not allowed: {value}")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SearchDatabaseBuildError(f"duplicate JSON key is not allowed: {key}")
        result[key] = value
    return result


def _strict_json(payload: bytes, *, context: str) -> Any:
    try:
        text = payload.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SearchDatabaseBuildError(f"invalid JSON in {context}: {exc}") from exc


def _canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def _bounded_file_bytes(path: Path, *, limit: int, context: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SearchDatabaseBuildError(f"cannot stat {context}: {exc}") from exc
    if not 0 < size <= limit:
        raise SearchDatabaseBuildError(f"{context} exceeds its byte limit")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise SearchDatabaseBuildError(f"cannot read {context}: {exc}") from exc
    if len(payload) != size:
        raise SearchDatabaseBuildError(f"{context} changed while it was read")
    return payload


def _valid_catalog_timestamp(value: object) -> str:
    text = str(value or "")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SearchDatabaseBuildError("manifest catalog_updated_at is invalid") from exc
    if not text or parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SearchDatabaseBuildError("manifest catalog_updated_at must include a timezone")
    return text


def _safe_shard_relative(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise SearchDatabaseBuildError(f"unsafe shard path: {value!r}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or SHARD_PATH_RE.fullmatch(value) is None:
        raise SearchDatabaseBuildError(f"unsafe shard path: {value!r}")
    return value


def _safe_existing_shard(catalog_root: Path, relative: str) -> Path:
    current = catalog_root
    for part in PurePosixPath(relative).parts:
        current /= part
        if _is_link_or_junction(current):
            raise SearchDatabaseBuildError(f"shard path traverses a link: {relative}")
    try:
        resolved = current.resolve(strict=True)
    except OSError as exc:
        raise SearchDatabaseBuildError(f"catalog shard is missing: {relative}") from exc
    if catalog_root not in resolved.parents or not resolved.is_file():
        raise SearchDatabaseBuildError(f"catalog shard is missing or unsafe: {relative}")
    return resolved


def _manifest_inputs(catalog_dir: Path) -> tuple[Path, bytes, dict[str, Any], list[dict[str, Any]]]:
    try:
        catalog_root = catalog_dir.resolve(strict=True)
    except OSError as exc:
        raise SearchDatabaseBuildError(f"catalog directory is unavailable: {catalog_dir}") from exc
    if not catalog_root.is_dir() or _is_link_or_junction(catalog_dir):
        raise SearchDatabaseBuildError(f"catalog path is not a safe directory: {catalog_dir}")
    manifest_path = catalog_root / "manifest.json"
    if _is_link_or_junction(manifest_path) or not manifest_path.is_file():
        raise SearchDatabaseBuildError(f"catalog manifest is missing or unsafe: {manifest_path}")
    manifest_payload = _bounded_file_bytes(
        manifest_path,
        limit=MAX_MANIFEST_BYTES,
        context="catalog manifest",
    )
    manifest = _strict_json(manifest_payload, context="manifest.json")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise SearchDatabaseBuildError("unsupported CVE catalog manifest schema")
    _valid_catalog_timestamp(manifest.get("catalog_updated_at"))

    totals = manifest.get("totals")
    if not isinstance(totals, dict):
        raise SearchDatabaseBuildError("manifest totals must be an object")
    expected_records = totals.get("catalog_records")
    expected_shards = totals.get("shards")
    if type(expected_records) is not int or not 0 <= expected_records <= MAX_CATALOG_RECORDS:
        raise SearchDatabaseBuildError("manifest catalog record count is invalid")

    raw_inventory = manifest.get("shard_manifest")
    if not isinstance(raw_inventory, list) or len(raw_inventory) > MAX_SHARDS:
        raise SearchDatabaseBuildError("manifest shard inventory is invalid or unbounded")
    if type(expected_shards) is not int or expected_shards != len(raw_inventory):
        raise SearchDatabaseBuildError("manifest shard count does not match its inventory")

    inventory: list[dict[str, Any]] = []
    paths: list[str] = []
    declared_records = 0
    for position, raw_entry in enumerate(raw_inventory):
        if not isinstance(raw_entry, dict) or set(raw_entry) != {
            "path",
            "records",
            "sha256",
            "bytes",
            "uncompressed_bytes",
        }:
            raise SearchDatabaseBuildError(f"manifest shard entry {position} has an invalid schema")
        relative = _safe_shard_relative(raw_entry.get("path"))
        digest = raw_entry.get("sha256")
        compressed_bytes = raw_entry.get("bytes")
        uncompressed_bytes = raw_entry.get("uncompressed_bytes")
        records = raw_entry.get("records")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise SearchDatabaseBuildError(f"manifest shard hash is invalid: {relative}")
        if (
            type(compressed_bytes) is not int
            or not 0 < compressed_bytes <= MAX_SHARD_COMPRESSED_BYTES
            or type(uncompressed_bytes) is not int
            or not 0 < uncompressed_bytes <= MAX_SHARD_UNCOMPRESSED_BYTES
            or type(records) is not int
            or not 0 < records <= MAX_CATALOG_RECORDS
        ):
            raise SearchDatabaseBuildError(f"manifest shard bounds are invalid: {relative}")
        inventory.append(dict(raw_entry))
        paths.append(relative)
        declared_records += records
        if declared_records > MAX_CATALOG_RECORDS:
            raise SearchDatabaseBuildError("manifest shard record total exceeds its limit")

    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise SearchDatabaseBuildError("manifest shard paths must be unique and sorted")
    if declared_records != expected_records:
        raise SearchDatabaseBuildError("manifest shard record counts do not match catalog total")

    canonical_inventory = [{"path": entry["path"], "sha256": entry["sha256"]} for entry in inventory]
    expected_set_digest = hashlib.sha256(_canonical_json_bytes(canonical_inventory)).hexdigest()
    declared_set_digest = manifest.get("shard_set_sha256")
    if (
        not isinstance(declared_set_digest, str)
        or SHA256_RE.fullmatch(declared_set_digest) is None
        or declared_set_digest != expected_set_digest
    ):
        raise SearchDatabaseBuildError("manifest shard-set digest does not match its inventory")

    shards_root = catalog_root / "shards"
    physical_paths: set[str] = set()
    if shards_root.exists():
        if _is_link_or_junction(shards_root) or not shards_root.is_dir():
            raise SearchDatabaseBuildError("catalog shards path is unsafe")
        for path in shards_root.rglob("*"):
            if path.is_dir() and not _is_link_or_junction(path):
                continue
            if _is_link_or_junction(path) or not path.is_file():
                raise SearchDatabaseBuildError(f"catalog shard tree contains an unsafe node: {path}")
            physical_paths.add(path.relative_to(catalog_root).as_posix())
    if physical_paths != set(paths):
        missing = sorted(set(paths) - physical_paths)
        orphaned = sorted(physical_paths - set(paths))
        raise SearchDatabaseBuildError(
            f"physical shard inventory mismatch: missing={missing[:5]}, orphaned={orphaned[:5]}"
        )

    return catalog_root, manifest_payload, manifest, inventory


def _expected_shard(cve: str) -> str:
    match = CVE_RE.fullmatch(cve)
    if match is None:
        return ""
    year, sequence = match.groups()
    return f"shards/{year}/{int(sequence) // 1000:04d}.jsonl.gz"


def _bounded_text(value: object, *, field: str, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SearchDatabaseBuildError(f"record {field} must be a string")
    text = re.sub(r"\s+", " ", value).strip()
    if (not text and not allow_empty) or len(text) > maximum:
        raise SearchDatabaseBuildError(f"record {field} is empty or unbounded")
    return text


def _product_name(value: object, *, field: str) -> str:
    if value is None:
        return ""
    text = _bounded_text(value, field=field, maximum=MAX_PRODUCT_NAME_CHARS, allow_empty=True)
    identity = text.casefold().strip()
    normalized_identity = re.sub(r"[\W_]+", " ", identity).strip()
    placeholders = PLACEHOLDER_PRODUCT_NAMES | {
        re.sub(r"[\W_]+", " ", item).strip() for item in PLACEHOLDER_PRODUCT_NAMES
    }
    if identity in PLACEHOLDER_PRODUCT_NAMES or normalized_identity in placeholders:
        return ""
    return text


def _product_search_text(record: dict[str, Any]) -> str:
    labels: list[str] = []
    seen: set[str] = set()
    for field in ("affected_data", "products"):
        rows = record.get(field)
        if not isinstance(rows, list) or len(rows) > MAX_PRODUCT_ROWS:
            raise SearchDatabaseBuildError(f"record {field} must be a bounded array")
        for position, row in enumerate(rows):
            if not isinstance(row, dict):
                raise SearchDatabaseBuildError(f"record {field}[{position}] must be an object")
            vendor = _product_name(row.get("vendor"), field=f"{field}[{position}].vendor")
            product = _product_name(row.get("product"), field=f"{field}[{position}].product")
            label = " ".join(value for value in (vendor, product) if value)
            identity = label.casefold()
            if not label or identity in seen:
                continue
            labels.append(label)
            seen.add(identity)
    return "\n".join(labels)


def _has_stable_markdown(record: dict[str, Any], *, cve: str) -> bool:
    recipe_kind = record.get("recipe_kind")
    if recipe_kind not in {"composed", "markdown-draft", "markdown-override"}:
        raise SearchDatabaseBuildError(f"record {cve} has an invalid recipe kind")
    markdown = record.get("markdown")
    if not isinstance(markdown, list) or len(markdown) > MAX_MARKDOWN_ROWS:
        raise SearchDatabaseBuildError(f"record {cve} has invalid Markdown metadata")

    stable_entries = 0
    for position, entry in enumerate(markdown):
        if not isinstance(entry, dict) or entry.get("cve") != cve:
            raise SearchDatabaseBuildError(f"record {cve} has invalid Markdown metadata at position {position}")
        maturity = entry.get("maturity")
        if not isinstance(maturity, str) or maturity.casefold() not in {
            "development",
            "stable",
        }:
            raise SearchDatabaseBuildError(f"record {cve} has invalid Markdown maturity at position {position}")
        if maturity.casefold() == "stable":
            content = entry.get("content_markdown")
            if not isinstance(content, str) or not content.strip():
                raise SearchDatabaseBuildError(f"record {cve} stable Markdown content is unavailable")
            stable_entries += 1

    if recipe_kind == "composed" and markdown:
        raise SearchDatabaseBuildError(f"record {cve} composed recipe has Markdown metadata")
    if recipe_kind == "markdown-draft" and (not markdown or stable_entries):
        raise SearchDatabaseBuildError(f"record {cve} draft Markdown metadata is inconsistent")
    if recipe_kind == "markdown-override" and stable_entries != 1:
        raise SearchDatabaseBuildError(f"record {cve} stable Markdown metadata is inconsistent")
    return recipe_kind == "markdown-override"


def _record_row(record: Any, *, relative: str) -> tuple[Any, ...]:
    if not isinstance(record, dict):
        raise SearchDatabaseBuildError(f"shard {relative} contains a non-object record")
    cve = record.get("cve")
    if not isinstance(cve, str) or CVE_RE.fullmatch(cve) is None:
        raise SearchDatabaseBuildError(f"shard {relative} contains an invalid CVE identity")
    if _expected_shard(cve) != relative:
        raise SearchDatabaseBuildError(f"record {cve} is stored in the wrong shard")
    title = _bounded_text(record.get("title"), field="title", maximum=MAX_TITLE_CHARS)
    summary = _bounded_text(record.get("summary"), field="summary", maximum=MAX_SUMMARY_CHARS)
    ecosystem = _bounded_text(record.get("ecosystem"), field="ecosystem", maximum=MAX_ECOSYSTEM_CHARS)
    severity = record.get("severity")
    if not isinstance(severity, str) or severity not in SEVERITY_RANK:
        raise SearchDatabaseBuildError(f"record {cve} has an invalid severity")
    score = record.get("score")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(float(score))
        or not 4.0 <= float(score) <= 10.0
    ):
        raise SearchDatabaseBuildError(f"record {cve} has an invalid score")
    published = record.get("published")
    if not isinstance(published, str):
        raise SearchDatabaseBuildError(f"record {cve} has an invalid publication date")
    try:
        published_date = date.fromisoformat(published)
    except ValueError as exc:
        raise SearchDatabaseBuildError(f"record {cve} has an invalid publication date") from exc
    kev = record.get("kev")
    if type(kev) is not bool:
        raise SearchDatabaseBuildError(f"record {cve} has an invalid KEV flag")
    primary_archetype = _bounded_text(record.get("archetype"), field="archetype", maximum=MAX_ARCHETYPE_CHARS)
    raw_archetypes = record.get("archetypes")
    if not isinstance(raw_archetypes, list) or not 0 < len(raw_archetypes) <= MAX_ARCHETYPES:
        raise SearchDatabaseBuildError(f"record {cve} has invalid archetypes")
    archetypes = [_bounded_text(value, field="archetypes", maximum=MAX_ARCHETYPE_CHARS) for value in raw_archetypes]
    if len(archetypes) != len({value.casefold() for value in archetypes}):
        raise SearchDatabaseBuildError(f"record {cve} repeats an archetype")
    if primary_archetype not in archetypes:
        raise SearchDatabaseBuildError(f"record {cve} primary archetype is absent from archetypes")
    products = _product_search_text(record)
    has_markdown = _has_stable_markdown(record, cve=cve)
    return (
        cve,
        title,
        summary,
        ecosystem,
        "\n".join(archetypes),
        products,
        severity,
        SEVERITY_RANK[severity],
        float(score),
        published,
        published_date.year,
        int(kev),
        int(has_markdown),
        relative,
    )


def _stream_shard_rows(
    catalog_root: Path,
    entry: dict[str, Any],
) -> Iterable[tuple[Any, ...]]:
    relative = str(entry["path"])
    path = _safe_existing_shard(catalog_root, relative)
    expected_compressed = int(entry["bytes"])
    expected_digest = str(entry["sha256"])
    expected_uncompressed = int(entry["uncompressed_bytes"])
    expected_records = int(entry["records"])
    uncompressed_bytes = 0
    records = 0
    previous_cve = ""
    try:
        with path.open("rb") as compressed_stream:
            if os.fstat(compressed_stream.fileno()).st_size != expected_compressed:
                raise SearchDatabaseBuildError(f"compressed byte count mismatch for shard {relative}")
            digest = hashlib.sha256()
            compressed_bytes = 0
            while chunk := compressed_stream.read(HASH_CHUNK_BYTES):
                compressed_bytes += len(chunk)
                if compressed_bytes > expected_compressed:
                    raise SearchDatabaseBuildError(f"compressed byte count exceeded manifest for shard {relative}")
                digest.update(chunk)
            if compressed_bytes != expected_compressed or digest.hexdigest() != expected_digest:
                raise SearchDatabaseBuildError(f"compressed hash mismatch for shard {relative}")
            compressed_stream.seek(0)

            with gzip.GzipFile(fileobj=compressed_stream, mode="rb") as stream:
                while True:
                    line = stream.readline(MAX_JSON_LINE_BYTES + 1)
                    if not line:
                        break
                    uncompressed_bytes += len(line)
                    if len(line) > MAX_JSON_LINE_BYTES:
                        raise SearchDatabaseBuildError(f"JSON line exceeds its limit in shard {relative}")
                    if uncompressed_bytes > expected_uncompressed:
                        raise SearchDatabaseBuildError(
                            f"uncompressed byte count exceeded manifest for shard {relative}"
                        )
                    if not line.endswith(b"\n") or not line.rstrip(b"\r\n"):
                        raise SearchDatabaseBuildError(f"shard {relative} is not canonical JSONL")
                    record = _strict_json(line.rstrip(b"\r\n"), context=f"shard {relative}")
                    row = _record_row(record, relative=relative)
                    cve = str(row[0])
                    if cve <= previous_cve:
                        raise SearchDatabaseBuildError(
                            f"shard {relative} contains duplicate or unsorted CVE identities"
                        )
                    previous_cve = cve
                    records += 1
                    if records > expected_records:
                        raise SearchDatabaseBuildError(f"record count exceeded manifest for shard {relative}")
                    yield row
    except (gzip.BadGzipFile, EOFError, OSError) as exc:
        raise SearchDatabaseBuildError(f"invalid gzip shard {relative}: {exc}") from exc
    if uncompressed_bytes != expected_uncompressed:
        raise SearchDatabaseBuildError(f"uncompressed byte count mismatch for shard {relative}")
    if records != expected_records:
        raise SearchDatabaseBuildError(f"record count mismatch for shard {relative}")


def _insert_batch(connection: sqlite3.Connection, batch: list[tuple[Any, ...]]) -> None:
    if not batch:
        return
    try:
        connection.executemany(INSERT_CVE_SQL, batch)
    except sqlite3.IntegrityError as exc:
        raise SearchDatabaseBuildError(
            "catalog contains a duplicate CVE or a record that violates the search schema"
        ) from exc
    batch.clear()


def _configure_database(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA page_size = 4096")
    connection.execute("PRAGMA auto_vacuum = NONE")
    connection.execute("PRAGMA journal_mode = OFF")
    connection.execute("PRAGMA synchronous = OFF")
    connection.execute("PRAGMA locking_mode = EXCLUSIVE")
    connection.execute("PRAGMA temp_store = FILE")
    connection.execute("PRAGMA cache_size = -32768")
    connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
    connection.execute(f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}")


def _metadata_rows(
    *,
    manifest_payload: bytes,
    manifest: dict[str, Any],
    record_count: int,
    shard_count: int,
) -> list[tuple[str, str]]:
    values = {
        "catalog_updated_at": _valid_catalog_timestamp(manifest.get("catalog_updated_at")),
        "database_schema_version": str(DATABASE_SCHEMA_VERSION),
        "fts_columns": "cve,title,summary,ecosystem,archetypes,products",
        "manifest_schema_version": str(MANIFEST_SCHEMA_VERSION),
        "manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
        "record_count": str(record_count),
        "shard_count": str(shard_count),
        "shard_set_sha256": str(manifest["shard_set_sha256"]),
    }
    return sorted(values.items())


def _build_temporary_database(
    temporary: Path,
    *,
    catalog_root: Path,
    manifest_payload: bytes,
    manifest: dict[str, Any],
    inventory: list[dict[str, Any]],
) -> dict[str, int | str]:
    connection = sqlite3.connect(temporary)
    try:
        _configure_database(connection)
        connection.executescript(CREATE_SCHEMA_SQL)
        connection.execute("BEGIN IMMEDIATE")
        inserted = 0
        batch: list[tuple[Any, ...]] = []
        for entry in inventory:
            for row in _stream_shard_rows(catalog_root, entry):
                batch.append(row)
                inserted += 1
                if len(batch) >= INSERT_BATCH_SIZE:
                    _insert_batch(connection, batch)
        _insert_batch(connection, batch)
        expected_records = int(manifest["totals"]["catalog_records"])
        if inserted != expected_records:
            raise SearchDatabaseBuildError(
                f"inserted record count {inserted} does not match manifest {expected_records}"
            )
        actual_records = connection.execute("SELECT count(*) FROM cves").fetchone()[0]
        if actual_records != expected_records:
            raise SearchDatabaseBuildError("SQLite record count does not match manifest")

        connection.executescript(CREATE_INDEXES_SQL)
        try:
            connection.executescript(CREATE_FTS_SQL)
        except sqlite3.OperationalError as exc:
            raise SearchDatabaseBuildError("this SQLite build does not provide FTS5") from exc
        connection.execute("INSERT INTO cve_fts(cve_fts) VALUES('rebuild')")
        fts_records = connection.execute("SELECT count(*) FROM cve_fts").fetchone()[0]
        if fts_records != expected_records:
            raise SearchDatabaseBuildError("SQLite FTS record count does not match manifest")
        connection.execute("INSERT INTO cve_fts(cve_fts) VALUES('integrity-check')")
        connection.executemany(
            "INSERT INTO metadata(key, value) VALUES (?, ?)",
            _metadata_rows(
                manifest_payload=manifest_payload,
                manifest=manifest,
                record_count=inserted,
                shard_count=len(inventory),
            ),
        )
        connection.commit()
        connection.execute("ANALYZE")
        connection.commit()
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        if integrity != [("ok",)]:
            raise SearchDatabaseBuildError(f"SQLite integrity check failed: {integrity[:3]}")
        return {
            "records": inserted,
            "shards": len(inventory),
            "manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
            "shard_set_sha256": str(manifest["shard_set_sha256"]),
        }
    except sqlite3.DatabaseError as exc:
        connection.rollback()
        if isinstance(exc, sqlite3.IntegrityError):
            raise SearchDatabaseBuildError("SQLite rejected a duplicate or invalid CVE record") from exc
        raise SearchDatabaseBuildError(f"SQLite search database build failed: {exc}") from exc
    finally:
        connection.close()


def _cleanup_temporary_database(path: Path) -> None:
    for candidate in (
        path,
        Path(str(path) + "-journal"),
        Path(str(path) + "-wal"),
        Path(str(path) + "-shm"),
    ):
        try:
            candidate.unlink(missing_ok=True)
        except OSError:
            pass


def _flush_for_publication(path: Path) -> None:
    try:
        with path.open("r+b") as stream:
            os.fsync(stream.fileno())
    except OSError as exc:
        raise SearchDatabaseBuildError(f"cannot flush completed search database: {exc}") from exc


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise SearchDatabaseBuildError("cannot hash completed search database") from exc
    return digest.hexdigest()


def _flush_directory(path: Path) -> None:
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, os.O_RDONLY | directory_flag)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _publish_metadata(path: Path, result: dict[str, int | str]) -> None:
    metadata_path = path.expanduser().absolute()
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    if _is_link_or_junction(metadata_path) or (
        metadata_path.exists() and not metadata_path.is_file()
    ):
        raise SearchDatabaseBuildError(f"metadata output path is unsafe: {metadata_path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{metadata_path.name}.",
        suffix=".tmp",
        dir=metadata_path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical_json_bytes(result))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, metadata_path)
        _flush_directory(metadata_path.parent)
    finally:
        _cleanup_temporary_database(temporary)


def build_search_database(
    catalog_dir: Path,
    output_path: Path,
    *,
    metadata_path: Path | None = None,
) -> dict[str, int | str]:
    """Build and atomically publish a verified runtime SQLite search database."""

    catalog_root, manifest_payload, manifest, inventory = _manifest_inputs(catalog_dir)
    output = output_path.expanduser().absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    if _is_link_or_junction(output) or (output.exists() and not output.is_file()):
        raise SearchDatabaseBuildError(f"output path is unsafe: {output}")
    resolved_output = output.resolve(strict=False)
    if resolved_output == catalog_root or catalog_root in resolved_output.parents:
        raise SearchDatabaseBuildError("output path cannot be inside the source catalog")
    metadata_output: Path | None = None
    if metadata_path is not None:
        metadata_output = metadata_path.expanduser().absolute()
        resolved_metadata = metadata_output.resolve(strict=False)
        if metadata_output == output:
            raise SearchDatabaseBuildError("metadata output must differ from the database output")
        if resolved_metadata == catalog_root or catalog_root in resolved_metadata.parents:
            raise SearchDatabaseBuildError("metadata output cannot be inside the source catalog")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        result = _build_temporary_database(
            temporary,
            catalog_root=catalog_root,
            manifest_payload=manifest_payload,
            manifest=manifest,
            inventory=inventory,
        )
        result["bytes"] = temporary.stat().st_size
        _flush_for_publication(temporary)
        result["database_sha256"] = _file_sha256(temporary)
        os.replace(temporary, output)
        _flush_directory(output.parent)
        if metadata_output is not None:
            _publish_metadata(metadata_output, result)
        return result
    finally:
        _cleanup_temporary_database(temporary)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the verified SQLite FTS5 artifact for the sharded CVE catalog.")
    parser.add_argument(
        "--catalog",
        type=Path,
        default=DEFAULT_CATALOG,
        help=f"catalog directory containing manifest.json (default: {DEFAULT_CATALOG})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"runtime SQLite output path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--metadata-output",
        type=Path,
        help="optional atomic JSON sidecar containing the trusted completed-database digest",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = build_search_database(
            args.catalog,
            args.output,
            metadata_path=args.metadata_output,
        )
    except (OSError, SearchDatabaseBuildError) as exc:
        print(f"CVE search database build failed: {exc}", file=os.sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
