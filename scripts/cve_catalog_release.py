#!/usr/bin/env python3
"""Build, verify, and transactionally hydrate immutable CVE catalog releases.

The descriptor is canonical JSON and its SHA-256 is the release identity.
Catalog bytes are a deterministic gzip-compressed USTAR blob stored below an
OCI-shaped ``blobs/sha256/<digest>`` path. Validation and hydration require an
independently supplied descriptor digest, so an internally consistent but
unapproved descriptor/blob pair cannot select its own trust root.

Hydration uses a per-target OS lock plus a durable recovery journal. Archive
bytes are fully authenticated, boundedly decompressed, parsed without tarfile's
metadata extensions, and validated as a catalog before the active directory is
renamed. Cross-platform filesystems cannot atomically exchange two non-empty
directories, so the journal makes the two-rename commit recoverable after a
crash while the lock excludes cooperative concurrent hydrators.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import stat
import sys
import tarfile
import tempfile
import uuid
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterator

try:
    from scripts.cve_ai_enrichment import recipe_ready
except ModuleNotFoundError:  # Direct ``python scripts/cve_catalog_release.py`` execution.
    from cve_ai_enrichment import recipe_ready  # type: ignore[no-redef]


RELEASE_SCHEMA = "security-recipes.cve-catalog-release"
RELEASE_SCHEMA_VERSION = 1
CATALOG_MANIFEST_SCHEMA_VERSION = 2
BLOB_MEDIA_TYPE = "application/vnd.security-recipes.cve-catalog.v1.tar+gzip"
HYDRATED_MARKER = ".catalog-release.json"
JOURNAL_SCHEMA = "security-recipes.cve-catalog-hydration-journal"
JOURNAL_SCHEMA_VERSION = 1

SHA256_RE = re.compile(r"[0-9a-f]{64}")
SHARD_PATH_RE = re.compile(r"shards/(\d{4})/(\d{4,})\.jsonl\.gz")
CVE_RE = re.compile(r"CVE-(\d{4})-(\d{4,})")
OWNED_TOKEN_RE = re.compile(r"[0-9a-f]{32}")

MAX_DESCRIPTOR_BYTES = 16 * 1024
MAX_JOURNAL_BYTES = 16 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_CATALOG_RECORDS = 1_000_000
MAX_ARCHIVE_MEMBERS = 100_000
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_BLOB_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_NESTED_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
MAX_SHARD_COMPRESSED_BYTES = 8 * 1024 * 1024
MAX_SHARD_UNCOMPRESSED_BYTES = 32 * 1024 * 1024
MAX_JSON_LINE_BYTES = 1024 * 1024
COPY_CHUNK_BYTES = 1024 * 1024
TAR_BLOCK_BYTES = 512
TAR_END_BLOCKS = 2

_DESCRIPTOR_KEYS = {
    "schema",
    "schema_version",
    "record_count",
    "shard_set_sha256",
    "manifest_sha256",
    "blob_media_type",
    "blob_sha256",
    "blob_size",
    "previous_release_sha256",
}
_JOURNAL_KEYS = {
    "schema",
    "schema_version",
    "target_name",
    "staging_name",
    "backup_name",
    "descriptor_sha256",
    "phase",
}
_JOURNAL_PHASES = {"prepared", "switching", "old_moved", "committed", "cleanup_pending"}
_WINDOWS_INVALID_CHARS = frozenset('<>:"\\|?*')
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_BROWSER_INDEX_FIELDS = [
    "cve",
    "title",
    "severity",
    "score",
    "published",
    "ecosystem_index",
    "kev",
    "archetype_indexes",
    "has_markdown",
]
_BROWSER_SEVERITY_CODES = {"medium": 0, "high": 1, "critical": 2}
_BROWSER_SEVERITY_NAMES = {
    str(code): severity for severity, code in _BROWSER_SEVERITY_CODES.items()
}


class CatalogReleaseError(ValueError):
    """A catalog release is malformed, unsafe, incomplete, or corrupt."""


@dataclass(frozen=True)
class CatalogIdentity:
    record_count: int
    shard_set_sha256: str
    manifest_sha256: str


@dataclass(frozen=True)
class ValidatedRelease:
    descriptor_sha256: str
    record_count: int
    shard_set_sha256: str
    manifest_sha256: str
    retained_backup: Path | None = None


@dataclass(frozen=True)
class PackageResult:
    descriptor_path: Path
    blob_path: Path
    descriptor_sha256: str
    blob_sha256: str
    blob_size: int


@dataclass(frozen=True)
class ShardInspection:
    compressed_bytes: int
    sha256: str
    uncompressed_bytes: int
    records: int


@dataclass(frozen=True)
class MemberInspection:
    size: int
    sha256: str
    shard: ShardInspection | None = None
    expanded_bytes: int | None = None
    records: int | None = None
    year: str | None = None
    catalog_updated_at: str | None = None


@dataclass(frozen=True)
class CatalogFile:
    relative: str
    path: Path
    size: int
    device: int
    inode: int
    modified_ns: int


class CatalogProjectionLedger:
    """Disk-backed exact comparisons between authoritative and projected records."""

    _COLUMNS = {
        "expected_complete": "expected_complete",
        "actual_complete": "actual_complete",
        "expected_browser": "expected_browser",
        "actual_browser": "actual_browser",
        "expected_search": "expected_search",
        "actual_search": "actual_search",
    }

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.connection.execute(
            """
            CREATE TABLE projections (
                cve TEXT PRIMARY KEY,
                expected_complete BLOB,
                actual_complete BLOB,
                expected_browser BLOB,
                actual_browser BLOB,
                expected_search BLOB,
                actual_search BLOB,
                search_required INTEGER
            ) WITHOUT ROWID
            """
        )

    def record(self, view: str, record: dict[str, Any]) -> None:
        column = self._COLUMNS[view]
        cve = record.get("cve")
        if not isinstance(cve, str) or CVE_RE.fullmatch(cve) is None:
            raise CatalogReleaseError(f"catalog {view} projection has an invalid CVE identity")
        digest = hashlib.sha256(_canonical_json_bytes(record)).digest()
        self.connection.execute("INSERT OR IGNORE INTO projections (cve) VALUES (?)", (cve,))
        updated = self.connection.execute(
            f"UPDATE projections SET {column} = ? WHERE cve = ? AND {column} IS NULL",
            (digest, cve),
        )
        if updated.rowcount != 1:
            raise CatalogReleaseError(f"catalog {view} projection contains duplicate CVE identity: {cve}")

    def validate(self, *, record_count: int) -> None:
        self.connection.commit()
        authoritative = self.connection.execute(
            "SELECT COUNT(*) FROM projections WHERE expected_complete IS NOT NULL"
        ).fetchone()[0]
        if authoritative != record_count:
            raise CatalogReleaseError(
                "authoritative shard record count does not match the catalog manifest"
            )
        checks = (
            (
                "complete index",
                "expected_complete IS NULL OR actual_complete IS NULL "
                "OR expected_complete != actual_complete",
            ),
            (
                "browser index",
                "expected_browser IS NULL OR actual_browser IS NULL "
                "OR expected_browser != actual_browser",
            ),
            (
                "search index",
                "search_required IS NULL "
                "OR (search_required = 1 AND "
                "(actual_search IS NULL OR expected_search != actual_search)) "
                "OR (search_required = 0 AND actual_search IS NOT NULL)",
            ),
        )
        for label, predicate in checks:
            mismatch = self.connection.execute(
                f"SELECT cve FROM projections WHERE {predicate} LIMIT 1"
            ).fetchone()
            if mismatch is not None:
                raise CatalogReleaseError(
                    f"{label} projection disagrees with authoritative shard record: {mismatch[0]}"
                )

    def set_search_required(self, cve: str, *, required: bool) -> None:
        updated = self.connection.execute(
            "UPDATE projections SET search_required = ? "
            "WHERE cve = ? AND search_required IS NULL",
            (int(required), cve),
        )
        if updated.rowcount != 1:
            raise CatalogReleaseError(
                f"catalog authoritative projection contains duplicate CVE identity: {cve}"
            )


@dataclass
class CatalogValidationState:
    expected_records: int
    ledger: CatalogProjectionLedger
    actual_records: int = 0
    nested_uncompressed_bytes: int = 0
    actual_complete_records: int = 0
    actual_browser_records: int = 0
    actual_search_records: int = 0

    def add_nested_bytes(self, size: int) -> None:
        self.nested_uncompressed_bytes += size
        if self.nested_uncompressed_bytes > MAX_NESTED_UNCOMPRESSED_BYTES:
            raise CatalogReleaseError("nested catalog gzip assets expand beyond their aggregate limit")

    def add_authoritative_record(self, record: dict[str, Any], *, shard: str) -> None:
        self.actual_records += 1
        if self.actual_records > self.expected_records or self.actual_records > MAX_CATALOG_RECORDS:
            raise CatalogReleaseError("authoritative shard record count exceeds its expected limit")
        complete = _project_complete_index_record(record, shard=shard)
        self.ledger.record("expected_complete", complete)
        self.ledger.record("expected_browser", _project_browser_record(complete))
        self.ledger.record("expected_search", _project_search_record(record))
        self.ledger.set_search_required(
            str(record["cve"]),
            required=_search_record_required(record),
        )

    def add_projection_record(self, view: str) -> None:
        attribute = f"actual_{view}_records"
        count = int(getattr(self, attribute)) + 1
        setattr(self, attribute, count)
        if count > self.expected_records or count > MAX_CATALOG_RECORDS:
            raise CatalogReleaseError(
                f"catalog {view} projection record count exceeds its expected limit"
            )


@contextmanager
def _projection_ledger() -> Iterator[CatalogProjectionLedger]:
    with tempfile.TemporaryDirectory(prefix="security-recipes-catalog-projections-") as directory:
        connection = sqlite3.connect(str(Path(directory) / "projections.sqlite3"))
        try:
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            yield CatalogProjectionLedger(connection)
        finally:
            connection.close()


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _normalize_space(value: object, *, limit: int | None = None) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if limit and len(text) > limit:
        text = text[: max(1, limit - 1)].rstrip(" ,;:-") + "…"
    return text


def _stable_markdown_entry(record: dict[str, Any]) -> dict[str, Any] | None:
    cve = str(record.get("cve") or "")
    markdown = record.get("markdown")
    stable = (
        [
            entry
            for entry in markdown
            if isinstance(entry, dict)
            and entry.get("cve") == cve
            and str(entry.get("maturity") or "").lower() == "stable"
        ]
        if isinstance(markdown, list)
        else []
    )
    return stable[0] if len(stable) == 1 else None


def _search_record_required(record: dict[str, Any]) -> bool:
    if record.get("recipe_kind") == "markdown-override":
        return True
    markdown = record.get("markdown")
    human_review_blocked = isinstance(markdown, list) and any(
        isinstance(entry, dict)
        and str(entry.get("maturity") or "").strip().casefold() == "development"
        and str(entry.get("ai_enrichment_review_status") or "").strip().casefold()
        == "human-reviewed-development-draft"
        for entry in markdown
    )
    return recipe_ready(record.get("ai_enrichment"), record) and not human_review_blocked


def _record_page_lastmod(record: dict[str, Any]) -> str:
    significant_dates: list[str] = []
    stable = _stable_markdown_entry(record)
    if stable:
        reviewed_date = str(stable.get("lastmod") or stable.get("date") or "")
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", reviewed_date):
            try:
                date.fromisoformat(reviewed_date)
            except ValueError:
                reviewed_date = ""
            if reviewed_date:
                significant_dates.append(reviewed_date)
    else:
        enrichment = record.get("ai_enrichment")
        if isinstance(enrichment, dict) and enrichment.get("status") == "complete":
            generated_at = str(enrichment.get("generated_at") or "").strip()
            match = re.match(r"^(\d{4}-\d{2}-\d{2})(?:T|$)", generated_at)
            if match:
                try:
                    date.fromisoformat(match.group(1))
                except ValueError:
                    pass
                else:
                    significant_dates.append(match.group(1))
    if not significant_dates:
        return ""
    source_modified = str(record.get("last_modified") or "").strip()
    source_match = re.match(r"^(\d{4}-\d{2}-\d{2})(?:T|$)", source_modified)
    if source_match:
        try:
            date.fromisoformat(source_match.group(1))
        except ValueError:
            pass
        else:
            significant_dates.append(source_match.group(1))
    return max(significant_dates)


def _project_complete_index_record(record: dict[str, Any], *, shard: str) -> dict[str, Any]:
    try:
        compact: dict[str, Any] = {
            "cve": record["cve"],
            "title": record["title"],
            "severity": record["severity"],
            "score": record["score"],
            "published": record["published"],
            "ecosystem": record["ecosystem"],
            "kev": record["kev"],
            "archetype": record["archetype"],
            "archetypes": record["archetypes"],
            "has_markdown": record["recipe_kind"] == "markdown-override",
            "shard": shard,
        }
    except KeyError as exc:
        raise CatalogReleaseError(
            f"authoritative shard record is missing projection field: {exc.args[0]}"
        ) from exc
    reviewed = _stable_markdown_entry(record)
    if reviewed:
        page_title = _normalize_space(reviewed.get("title"), limit=200)
        page_description = _normalize_space(reviewed.get("description"), limit=500)
        if page_title:
            compact["page_title"] = page_title
        if page_description:
            compact["page_description"] = page_description
    page_lastmod = _record_page_lastmod(record)
    if page_lastmod:
        compact["page_lastmod"] = page_lastmod
    return compact


def _project_browser_record(complete: dict[str, Any]) -> dict[str, Any]:
    return {
        field: complete[field]
        for field in (
            "cve",
            "title",
            "severity",
            "score",
            "published",
            "ecosystem",
            "kev",
            "archetypes",
            "has_markdown",
        )
    }


def _project_search_record(record: dict[str, Any]) -> dict[str, Any]:
    product_rows: list[dict[str, str]] = []
    product_seen: set[tuple[str, str]] = set()
    for product in record.get("products") or []:
        if not isinstance(product, dict):
            continue
        vendor = _normalize_space(product.get("vendor"), limit=160)
        name = _normalize_space(product.get("product"), limit=200)
        identity = (vendor.casefold(), name.casefold())
        if not any(identity) or identity in product_seen:
            continue
        product_rows.append({"vendor": vendor, "product": name})
        product_seen.add(identity)
        if len(product_rows) >= 8:
            break
    try:
        compact: dict[str, Any] = {
            "cve": record["cve"],
            "title": record["title"],
            "severity": record["severity"],
            "score": record["score"],
            "published": record["published"],
            "ecosystem": record["ecosystem"],
            "kev": record["kev"] is True,
            "archetypes": list(record.get("archetypes") or []),
            "cwes": list(record.get("cwes") or [])[:12],
            "products": product_rows,
            "qualification": (
                "stable_markdown"
                if record["recipe_kind"] == "markdown-override"
                else "recipe_ready_ai"
            ),
        }
    except KeyError as exc:
        raise CatalogReleaseError(
            f"authoritative shard record is missing search projection field: {exc.args[0]}"
        ) from exc
    reviewed = _stable_markdown_entry(record)
    if reviewed:
        page_title = _normalize_space(reviewed.get("title"), limit=200)
        page_description = _normalize_space(reviewed.get("description"), limit=500)
        if page_title:
            compact["page_title"] = page_title
        if page_description:
            compact["page_description"] = page_description
    page_lastmod = _record_page_lastmod(record)
    if page_lastmod:
        compact["page_lastmod"] = page_lastmod
    return compact


def _reject_json_constant(value: str) -> None:
    raise CatalogReleaseError(f"non-finite JSON value is not allowed: {value}")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogReleaseError(f"duplicate JSON key is not allowed: {key}")
        result[key] = value
    return result


def _strict_json(payload: bytes, *, context: str) -> Any:
    try:
        return json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogReleaseError(f"invalid JSON in {context}: {exc}") from exc


def _valid_digest(value: object, *, field: str, allow_none: bool = False) -> str | None:
    if allow_none and value is None:
        return None
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CatalogReleaseError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _stat_is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE)


def _is_link_or_junction(path: Path) -> bool:
    """Detect POSIX links and Windows reparse points on Python 3.10+."""

    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise CatalogReleaseError(f"cannot inspect filesystem path {path}: {exc}") from exc
    return stat.S_ISLNK(metadata.st_mode) or _stat_is_reparse(metadata)


def _reject_reparse_components(path: Path, *, include_leaf: bool) -> None:
    absolute = Path(os.path.abspath(path))
    chain = list(reversed(absolute.parents))
    if include_leaf:
        chain.append(absolute)
    for component in chain:
        if os.path.lexists(component) and _is_link_or_junction(component):
            raise CatalogReleaseError(f"filesystem path traverses a link or reparse point: {component}")


def _assert_regular_metadata(metadata: os.stat_result, *, context: str) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or _stat_is_reparse(metadata)
        or getattr(metadata, "st_nlink", 1) != 1
    ):
        raise CatalogReleaseError(f"{context} is not a private regular file")


@contextmanager
def _open_private_regular(path: Path, *, context: str) -> Iterator[BinaryIO]:
    _reject_reparse_components(path, include_leaf=True)
    try:
        before = os.lstat(path)
        _assert_regular_metadata(before, context=context)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except (OSError, CatalogReleaseError) as exc:
        if isinstance(exc, CatalogReleaseError):
            raise
        raise CatalogReleaseError(f"cannot open {context}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        _assert_regular_metadata(opened, context=context)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise CatalogReleaseError(f"{context} changed while it was opened")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            yield stream
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_private_file(path: Path, *, limit: int, context: str) -> bytes:
    with _open_private_regular(path, context=context) as stream:
        size = os.fstat(stream.fileno()).st_size
        if not 0 < size <= limit:
            raise CatalogReleaseError(f"{context} exceeds its byte limit")
        payload = stream.read(limit + 1)
        if len(payload) != size or len(payload) > limit:
            raise CatalogReleaseError(f"{context} changed or exceeds its byte limit")
        return payload


def _sha256_stream(stream: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(COPY_CHUNK_BYTES):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _sha256_private_file(path: Path, *, limit: int, context: str) -> tuple[str, int]:
    with _open_private_regular(path, context=context) as stream:
        declared = os.fstat(stream.fileno()).st_size
        if not 0 <= declared <= limit:
            raise CatalogReleaseError(f"{context} exceeds its byte limit")
        digest, size = _sha256_stream(stream)
        if size != declared:
            raise CatalogReleaseError(f"{context} changed while it was read")
        return digest, size


def _safe_member_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise CatalogReleaseError(f"unsafe archive member path: {value!r}")
    if "\x00" in value or "\\" in value:
        raise CatalogReleaseError(f"unsafe archive member path: {value!r}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or pure.as_posix() != value or any(
        part in {"", ".", ".."} for part in pure.parts
    ):
        raise CatalogReleaseError(f"unsafe archive member path: {value!r}")
    for part in pure.parts:
        if (
            part.endswith((" ", "."))
            or any(ord(character) < 32 for character in part)
            or any(character in _WINDOWS_INVALID_CHARS for character in part)
            or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES
        ):
            raise CatalogReleaseError(f"unsafe archive member path: {value!r}")
    return value


def _expected_shard(cve: str) -> str:
    match = CVE_RE.fullmatch(cve)
    if match is None:
        return ""
    year, sequence = match.groups()
    return f"shards/{year}/{int(sequence) // 1000:04d}.jsonl.gz"


def _inspect_shard(
    relative: str,
    compressed: bytes,
    *,
    state: CatalogValidationState,
) -> ShardInspection:
    if SHARD_PATH_RE.fullmatch(relative) is None:
        raise CatalogReleaseError(f"catalog shard path is invalid: {relative}")
    if not 0 < len(compressed) <= MAX_SHARD_COMPRESSED_BYTES:
        raise CatalogReleaseError(f"catalog shard compressed size is invalid: {relative}")
    expanded = 0
    records = 0
    previous_cve = ""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as stream:
            while True:
                line = stream.readline(MAX_JSON_LINE_BYTES + 1)
                if not line:
                    break
                expanded += len(line)
                state.add_nested_bytes(len(line))
                if len(line) > MAX_JSON_LINE_BYTES:
                    raise CatalogReleaseError(f"JSON line exceeds its limit in shard {relative}")
                if expanded > MAX_SHARD_UNCOMPRESSED_BYTES:
                    raise CatalogReleaseError(f"expanded shard exceeds its limit: {relative}")
                if not line.endswith(b"\n") or not line.rstrip(b"\r\n"):
                    raise CatalogReleaseError(f"shard {relative} is not canonical JSONL")
                record = _strict_json(line.rstrip(b"\r\n"), context=f"shard {relative}")
                if not isinstance(record, dict):
                    raise CatalogReleaseError(f"shard {relative} contains a non-object JSON record")
                cve = record.get("cve")
                if not isinstance(cve, str) or CVE_RE.fullmatch(cve) is None:
                    raise CatalogReleaseError(f"shard {relative} contains an invalid CVE identity")
                if _expected_shard(cve) != relative:
                    raise CatalogReleaseError(f"CVE {cve} is stored in the wrong shard: {relative}")
                if cve <= previous_cve:
                    raise CatalogReleaseError(
                        f"shard {relative} contains duplicate or unsorted CVE identities"
                    )
                previous_cve = cve
                records += 1
                if records > MAX_CATALOG_RECORDS:
                    raise CatalogReleaseError(f"shard record count exceeds its limit: {relative}")
                state.add_authoritative_record(record, shard=relative)
    except CatalogReleaseError:
        raise
    except (gzip.BadGzipFile, EOFError, OSError, zlib.error) as exc:
        raise CatalogReleaseError(f"invalid gzip shard {relative}: {exc}") from exc
    if records == 0:
        raise CatalogReleaseError(f"catalog shard is empty: {relative}")
    return ShardInspection(
        compressed_bytes=len(compressed),
        sha256=hashlib.sha256(compressed).hexdigest(),
        uncompressed_bytes=expanded,
        records=records,
    )


def _gunzip_asset(
    relative: str,
    compressed: bytes,
    *,
    state: CatalogValidationState,
) -> bytes:
    expanded = bytearray()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as stream:
            while chunk := stream.read(COPY_CHUNK_BYTES):
                expanded.extend(chunk)
                state.add_nested_bytes(len(chunk))
                if len(expanded) > MAX_MEMBER_BYTES:
                    raise CatalogReleaseError(f"expanded catalog asset exceeds its limit: {relative}")
    except CatalogReleaseError:
        raise
    except (gzip.BadGzipFile, EOFError, OSError, zlib.error) as exc:
        raise CatalogReleaseError(f"invalid gzip catalog asset {relative}: {exc}") from exc
    return bytes(expanded)


def _inspect_catalog_member(
    relative: str,
    payload: bytes,
    *,
    state: CatalogValidationState,
) -> tuple[MemberInspection, bytes | None]:
    digest = hashlib.sha256(payload).hexdigest()
    if relative.startswith("shards/"):
        shard = _inspect_shard(relative, payload, state=state)
        return MemberInspection(size=len(payload), sha256=digest, shard=shard), None

    retained_payload: bytes | None = None
    if relative == "browser-index.json.gz":
        expanded = _gunzip_asset(relative, payload, state=state)
        value = _strict_json(expanded, context=relative)
        if (
            not isinstance(value, dict)
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != CATALOG_MANIFEST_SCHEMA_VERSION
            or set(value) != {
                "schema_version",
                "severity_codes",
                "fields",
                "ecosystems",
                "archetypes",
                "records",
            }
            or value.get("severity_codes") != _BROWSER_SEVERITY_NAMES
            or value.get("fields") != _BROWSER_INDEX_FIELDS
            or not isinstance(value.get("ecosystems"), list)
            or not isinstance(value.get("archetypes"), list)
            or not isinstance(value.get("records"), list)
        ):
            raise CatalogReleaseError("browser index has an invalid schema")
        ecosystems = value["ecosystems"]
        archetypes = value["archetypes"]
        for label, dictionary in (("ecosystems", ecosystems), ("archetypes", archetypes)):
            if (
                any(not isinstance(item, str) or not item for item in dictionary)
                or dictionary != sorted(set(dictionary))
            ):
                raise CatalogReleaseError(f"browser index {label} dictionary is invalid")
        for position, row in enumerate(value["records"]):
            state.add_projection_record("browser")
            if not isinstance(row, list) or len(row) != len(_BROWSER_INDEX_FIELDS):
                raise CatalogReleaseError(f"browser index row {position} has an invalid width")
            ecosystem_index = row[5]
            archetype_indexes = row[7]
            if (
                type(row[2]) is not int
                or row[2] not in _BROWSER_SEVERITY_CODES.values()
                or type(ecosystem_index) is not int
                or not 0 <= ecosystem_index < len(ecosystems)
                or not isinstance(archetype_indexes, list)
                or any(
                    type(item) is not int or not 0 <= item < len(archetypes)
                    for item in archetype_indexes
                )
                or not isinstance(row[6], bool)
                or not isinstance(row[8], bool)
            ):
                raise CatalogReleaseError(f"browser index row {position} is invalid")
            state.ledger.record(
                "actual_browser",
                {
                    "cve": row[0],
                    "title": row[1],
                    "severity": _BROWSER_SEVERITY_NAMES[str(row[2])],
                    "score": row[3],
                    "published": row[4],
                    "ecosystem": ecosystems[ecosystem_index],
                    "kev": row[6],
                    "archetypes": [archetypes[item] for item in archetype_indexes],
                    "has_markdown": row[8],
                },
            )
        return (
            MemberInspection(
                size=len(payload),
                sha256=digest,
                expanded_bytes=len(expanded),
                records=len(value["records"]),
            ),
            None,
        )

    partition_match = re.fullmatch(r"indexes/(\d{4})\.json\.gz", relative)
    if partition_match is not None:
        expanded = _gunzip_asset(relative, payload, state=state)
        value = _strict_json(expanded, context=relative)
        year = partition_match.group(1)
        if (
            not isinstance(value, dict)
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != CATALOG_MANIFEST_SCHEMA_VERSION
            or value.get("year") != year
            or type(value.get("total")) is not int
            or not isinstance(value.get("records"), list)
            or value.get("total") != len(value["records"])
            or not isinstance(value.get("catalog_updated_at"), str)
        ):
            raise CatalogReleaseError(f"complete-index partition has an invalid schema: {relative}")
        previous_cve = ""
        for position, record in enumerate(value["records"]):
            state.add_projection_record("complete")
            if not isinstance(record, dict):
                raise CatalogReleaseError(
                    f"complete-index partition contains a non-object record: {relative}:{position}"
                )
            cve = record.get("cve")
            if not isinstance(cve, str) or CVE_RE.fullmatch(cve) is None or cve <= previous_cve:
                raise CatalogReleaseError(
                    f"complete-index partition has invalid or unsorted CVEs: {relative}"
                )
            published = record.get("published")
            if not isinstance(published, str) or not published.startswith(f"{year}-"):
                raise CatalogReleaseError(
                    f"complete-index record is in the wrong publication-year partition: {cve}"
                )
            previous_cve = cve
            state.ledger.record("actual_complete", record)
        return (
            MemberInspection(
                size=len(payload),
                sha256=digest,
                expanded_bytes=len(expanded),
                records=len(value["records"]),
                year=year,
                catalog_updated_at=value["catalog_updated_at"],
            ),
            None,
        )

    if relative in {
        "manifest.json",
        "index.json",
        "archetypes.json",
        "runtime-summary.json",
        "search-indexable.json",
    }:
        value = _strict_json(payload, context=relative)
        if not isinstance(value, dict):
            raise CatalogReleaseError(f"catalog JSON asset must contain an object: {relative}")
        if relative == "search-indexable.json":
            if set(value) != {"schema_version", "catalog_updated_at", "policy", "records"} or not isinstance(
                value.get("records"), list
            ):
                raise CatalogReleaseError("search index has an invalid schema")
            previous_cve = ""
            for position, record in enumerate(value["records"]):
                state.add_projection_record("search")
                if not isinstance(record, dict):
                    raise CatalogReleaseError(f"search index record {position} is not an object")
                cve = record.get("cve")
                if not isinstance(cve, str) or CVE_RE.fullmatch(cve) is None or cve <= previous_cve:
                    raise CatalogReleaseError("search index CVE identities must be unique and sorted")
                previous_cve = cve
                state.ledger.record("actual_search", record)
        retained_payload = payload
    return MemberInspection(size=len(payload), sha256=digest), retained_payload


def _declared_asset(
    value: object,
    *,
    field: str,
    expected_path: str,
) -> tuple[str, int, str]:
    if not isinstance(value, dict):
        raise CatalogReleaseError(f"catalog manifest {field} must be an object")
    path = _safe_member_path(value.get("path"))
    size = value.get("bytes")
    digest = _valid_digest(value.get("sha256"), field=f"catalog manifest {field} sha256")
    if path != expected_path:
        raise CatalogReleaseError(f"catalog manifest {field} path is unsupported: {path}")
    if type(size) is not int or not 0 < size <= MAX_MEMBER_BYTES:
        raise CatalogReleaseError(f"catalog manifest {field} byte count is invalid")
    return path, size, digest


def _validate_manifest_assets(
    manifest: dict[str, Any],
    *,
    members: dict[str, MemberInspection],
    payloads: dict[str, bytes],
    shard_paths: list[str],
    record_count: int,
) -> None:
    declared: dict[str, tuple[int, str]] = {}
    archetypes_path, archetypes_size, archetypes_digest = _declared_asset(
        manifest.get("archetypes_asset"),
        field="archetypes_asset",
        expected_path="archetypes.json",
    )
    declared[archetypes_path] = (archetypes_size, archetypes_digest)
    browser_value = manifest.get("browser_index")
    browser_path, browser_size, browser_digest = _declared_asset(
        browser_value,
        field="browser_index",
        expected_path="browser-index.json.gz",
    )
    if not isinstance(browser_value, dict):
        raise CatalogReleaseError("catalog manifest browser_index must be an object")
    browser_records = browser_value.get("records")
    browser_uncompressed = browser_value.get("uncompressed_bytes")
    if (
        type(browser_records) is not int
        or browser_records != record_count
        or type(browser_uncompressed) is not int
        or not 0 < browser_uncompressed <= MAX_MEMBER_BYTES
    ):
        raise CatalogReleaseError("catalog manifest browser_index bounds are invalid")
    declared[browser_path] = (browser_size, browser_digest)
    runtime_path, runtime_size, runtime_digest = _declared_asset(
        manifest.get("runtime_summary"),
        field="runtime_summary",
        expected_path="runtime-summary.json",
    )
    declared[runtime_path] = (runtime_size, runtime_digest)
    search_value = manifest.get("search_index")
    search_path, search_size, search_digest = _declared_asset(
        search_value,
        field="search_index",
        expected_path="search-indexable.json",
    )
    if (
        not isinstance(search_value, dict)
        or type(search_value.get("schema_version")) is not int
        or search_value.get("schema_version") != CATALOG_MANIFEST_SCHEMA_VERSION
        or type(search_value.get("records")) is not int
        or not 0 <= search_value["records"] <= record_count
        or not isinstance(search_value.get("policy"), str)
    ):
        raise CatalogReleaseError("catalog manifest search_index contract is invalid")
    declared[search_path] = (search_size, search_digest)

    complete = manifest.get("complete_index")
    if not isinstance(complete, dict) or set(complete) != {
        "format",
        "partitions",
        "path",
        "records",
    }:
        raise CatalogReleaseError("catalog manifest complete_index contract is invalid")
    if (
        complete.get("format") != "published-year-partitions"
        or complete.get("path") != "index.json"
        or type(complete.get("records")) is not int
        or complete.get("records") != record_count
        or not isinstance(complete.get("partitions"), list)
    ):
        raise CatalogReleaseError("catalog manifest complete_index identity is invalid")
    partitions = complete["partitions"]
    partition_years: list[str] = []
    partition_records = 0
    for position, partition in enumerate(partitions):
        if not isinstance(partition, dict) or set(partition) != {
            "bytes",
            "path",
            "records",
            "sha256",
            "uncompressed_bytes",
            "year",
        }:
            raise CatalogReleaseError(f"complete-index partition {position} has an invalid schema")
        year = partition.get("year")
        if not isinstance(year, str) or re.fullmatch(r"\d{4}", year) is None:
            raise CatalogReleaseError(f"complete-index partition {position} has an invalid year")
        expected_path = f"indexes/{year}.json.gz"
        path = _safe_member_path(partition.get("path"))
        size = partition.get("bytes")
        expanded = partition.get("uncompressed_bytes")
        records = partition.get("records")
        digest = _valid_digest(
            partition.get("sha256"),
            field=f"complete-index partition {year} sha256",
        )
        if (
            path != expected_path
            or type(size) is not int
            or not 0 < size <= MAX_MEMBER_BYTES
            or type(expanded) is not int
            or not 0 < expanded <= MAX_MEMBER_BYTES
            or type(records) is not int
            or records < 0
        ):
            raise CatalogReleaseError(f"complete-index partition bounds are invalid: {year}")
        partition_years.append(year)
        partition_records += records
        declared[path] = (size, digest)
        member = members.get(path)
        if (
            member is None
            or member.expanded_bytes != expanded
            or member.records != records
            or member.year != year
            or member.catalog_updated_at != manifest.get("catalog_updated_at")
        ):
            raise CatalogReleaseError(f"complete-index partition body disagrees with manifest: {year}")
    if partition_years != sorted(partition_years) or len(partition_years) != len(set(partition_years)):
        raise CatalogReleaseError("complete-index partition years must be unique and sorted")
    if partition_records != record_count:
        raise CatalogReleaseError("complete-index partition record counts do not match catalog total")

    for path, (size, digest) in declared.items():
        member = members.get(path)
        if member is None or (member.size, member.sha256) != (size, digest):
            raise CatalogReleaseError(f"catalog asset is missing or corrupt: {path}")
    browser_member = members.get(browser_path)
    if (
        browser_member is None
        or browser_member.expanded_bytes != browser_uncompressed
        or browser_member.records != browser_records
    ):
        raise CatalogReleaseError("browser index body disagrees with manifest")

    index_payload = payloads.get("index.json")
    if index_payload is None:
        raise CatalogReleaseError("complete index descriptor is missing")
    index_value = _strict_json(index_payload, context="index.json")
    if (
        not isinstance(index_value, dict)
        or set(index_value) != {
            "catalog_updated_at",
            "partition_key",
            "partitions",
            "schema_version",
            "scope",
            "total",
        }
        or type(index_value.get("schema_version")) is not int
        or index_value.get("schema_version") != CATALOG_MANIFEST_SCHEMA_VERSION
        or index_value.get("catalog_updated_at") != manifest.get("catalog_updated_at")
        or index_value.get("partition_key") != "published_year"
        or index_value.get("partitions") != partitions
        or index_value.get("scope") != manifest.get("scope")
        or type(index_value.get("total")) is not int
        or index_value.get("total") != record_count
    ):
        raise CatalogReleaseError("index.json does not match the complete_index manifest contract")

    search_payload = payloads.get(search_path)
    if search_payload is None:
        raise CatalogReleaseError("search index payload is missing")
    search_object = _strict_json(search_payload, context=search_path)
    if (
        not isinstance(search_object, dict)
        or type(search_object.get("schema_version")) is not int
        or search_object.get("schema_version") != CATALOG_MANIFEST_SCHEMA_VERSION
        or search_object.get("catalog_updated_at") != manifest.get("catalog_updated_at")
        or search_object.get("policy") != search_value.get("policy")
        or not isinstance(search_object.get("records"), list)
        or len(search_object["records"]) != search_value.get("records")
    ):
        raise CatalogReleaseError("search index body disagrees with manifest")

    expected_paths = {
        "manifest.json",
        "index.json",
        *shard_paths,
        *declared,
    }
    if set(members) != expected_paths:
        missing = sorted(expected_paths - set(members))
        extra = sorted(set(members) - expected_paths)
        raise CatalogReleaseError(
            f"catalog physical file set disagrees with manifest: missing={missing[:5]}, extra={extra[:5]}"
        )


def _load_manifest_identity(
    payload: bytes,
    *,
    members: dict[str, MemberInspection] | None = None,
    payloads: dict[str, bytes] | None = None,
    state: CatalogValidationState | None = None,
) -> CatalogIdentity:
    if not 0 < len(payload) <= MAX_MANIFEST_BYTES:
        raise CatalogReleaseError("catalog manifest exceeds its byte limit")
    manifest = _strict_json(payload, context="catalog manifest")
    if (
        not isinstance(manifest, dict)
        or type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != CATALOG_MANIFEST_SCHEMA_VERSION
    ):
        raise CatalogReleaseError("unsupported catalog manifest schema")
    totals = manifest.get("totals")
    if not isinstance(totals, dict):
        raise CatalogReleaseError("catalog manifest totals must be an object")
    record_count = totals.get("catalog_records")
    if type(record_count) is not int or not 0 <= record_count <= MAX_CATALOG_RECORDS:
        raise CatalogReleaseError("catalog manifest record count is invalid")
    inventory = manifest.get("shard_manifest")
    if not isinstance(inventory, list) or len(inventory) > MAX_ARCHIVE_MEMBERS:
        raise CatalogReleaseError("catalog shard inventory is invalid or unbounded")
    declared_shards = totals.get("shards")
    if type(declared_shards) is not int or declared_shards != len(inventory):
        raise CatalogReleaseError("catalog shard count does not match its inventory")

    identities: list[dict[str, str]] = []
    shard_paths: list[str] = []
    inventory_records = 0
    for position, entry in enumerate(inventory):
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "records",
            "sha256",
            "bytes",
            "uncompressed_bytes",
        }:
            raise CatalogReleaseError(f"catalog shard entry {position} has an invalid schema")
        relative = _safe_member_path(entry.get("path"))
        if SHARD_PATH_RE.fullmatch(relative) is None:
            raise CatalogReleaseError(f"catalog shard path is invalid: {relative}")
        digest = _valid_digest(entry.get("sha256"), field=f"catalog shard {relative} sha256")
        records = entry.get("records")
        compressed_bytes = entry.get("bytes")
        uncompressed_bytes = entry.get("uncompressed_bytes")
        if (
            type(records) is not int
            or not 0 < records <= MAX_CATALOG_RECORDS
            or type(compressed_bytes) is not int
            or not 0 < compressed_bytes <= MAX_SHARD_COMPRESSED_BYTES
            or type(uncompressed_bytes) is not int
            or not 0 < uncompressed_bytes <= MAX_SHARD_UNCOMPRESSED_BYTES
        ):
            raise CatalogReleaseError(f"catalog shard bounds are invalid: {relative}")
        inventory_records += records
        if inventory_records > MAX_CATALOG_RECORDS:
            raise CatalogReleaseError("catalog shard record total exceeds its limit")
        shard_paths.append(relative)
        identities.append({"path": relative, "sha256": digest})
        if members is not None:
            member = members.get(relative)
            if member is None or member.shard is None:
                raise CatalogReleaseError(f"catalog shard is missing or unvalidated: {relative}")
            shard = member.shard
            if (
                shard.sha256 != digest
                or shard.compressed_bytes != compressed_bytes
                or shard.uncompressed_bytes != uncompressed_bytes
                or shard.records != records
            ):
                raise CatalogReleaseError(f"catalog shard body disagrees with its manifest: {relative}")

    if shard_paths != sorted(shard_paths) or len(shard_paths) != len(set(shard_paths)):
        raise CatalogReleaseError("catalog shard paths must be unique and sorted")
    if inventory_records != record_count:
        raise CatalogReleaseError("catalog shard record counts do not match catalog total")
    expected_set = hashlib.sha256(_canonical_json_bytes(identities)).hexdigest()
    shard_set = _valid_digest(manifest.get("shard_set_sha256"), field="catalog shard_set_sha256")
    if shard_set != expected_set:
        raise CatalogReleaseError("catalog shard-set digest does not match its inventory")
    if members is not None:
        physical_shards = sorted(path for path in members if path.startswith("shards/"))
        if physical_shards != shard_paths:
            raise CatalogReleaseError("archive shard members do not exactly match the catalog manifest")
        if payloads is None:
            raise CatalogReleaseError("catalog asset payloads are unavailable for validation")
        _validate_manifest_assets(
            manifest,
            members=members,
            payloads=payloads,
            shard_paths=shard_paths,
            record_count=record_count,
        )
        if state is None:
            raise CatalogReleaseError("catalog semantic validation state is unavailable")
        state.ledger.validate(record_count=record_count)
    return CatalogIdentity(
        record_count=record_count,
        shard_set_sha256=shard_set,
        manifest_sha256=hashlib.sha256(payload).hexdigest(),
    )


def _portable_register(
    relative: str,
    *,
    is_directory: bool,
    portable_files: set[str],
    portable_directories: set[str],
) -> None:
    parts = tuple(part.casefold() for part in PurePosixPath(relative).parts)
    key = "/".join(parts)
    parent_keys = {"/".join(parts[:position]) for position in range(1, len(parts))}
    if key in portable_files or key in portable_directories or parent_keys & portable_files:
        raise CatalogReleaseError(f"catalog path has a portable collision: {relative}")
    if is_directory:
        portable_directories.add(key)
    else:
        portable_files.add(key)
        portable_directories.update(parent_keys)


def _catalog_files(catalog_dir: Path) -> tuple[Path, list[CatalogFile]]:
    _reject_reparse_components(catalog_dir, include_leaf=True)
    try:
        root = catalog_dir.resolve(strict=True)
    except OSError as exc:
        raise CatalogReleaseError(f"catalog directory is unavailable: {catalog_dir}") from exc
    if _is_link_or_junction(catalog_dir) or not root.is_dir():
        raise CatalogReleaseError(f"catalog path is not a safe directory: {catalog_dir}")

    files: list[CatalogFile] = []
    portable_files: set[str] = set()
    portable_directories: set[str] = set()
    aggregate_bytes = 0
    estimated_tar_bytes = TAR_BLOCK_BYTES * TAR_END_BLOCKS

    def visit(directory: Path, relative_parts: tuple[str, ...]) -> None:
        nonlocal aggregate_bytes, estimated_tar_bytes
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise CatalogReleaseError(f"cannot enumerate catalog directory {directory}: {exc}") from exc
        for entry in entries:
            path = Path(entry.path)
            relative = _safe_member_path("/".join((*relative_parts, entry.name)))
            if relative == HYDRATED_MARKER:
                raise CatalogReleaseError(f"catalog uses reserved release metadata path: {relative}")
            if _is_link_or_junction(path):
                raise CatalogReleaseError(f"catalog contains a link or reparse point: {relative}")
            try:
                metadata = os.lstat(path)
            except OSError as exc:
                raise CatalogReleaseError(f"cannot stat catalog member {relative}: {exc}") from exc
            if stat.S_ISDIR(metadata.st_mode):
                _portable_register(
                    relative,
                    is_directory=True,
                    portable_files=portable_files,
                    portable_directories=portable_directories,
                )
                visit(path, (*relative_parts, entry.name))
                continue
            _assert_regular_metadata(metadata, context=f"catalog member {relative}")
            if metadata.st_size > MAX_MEMBER_BYTES:
                raise CatalogReleaseError(f"catalog member exceeds its byte limit: {relative}")
            _portable_register(
                relative,
                is_directory=False,
                portable_files=portable_files,
                portable_directories=portable_directories,
            )
            try:
                tarfile.TarInfo(relative).tobuf(
                    format=tarfile.USTAR_FORMAT,
                    encoding="utf-8",
                    errors="strict",
                )
            except (UnicodeError, ValueError) as exc:
                raise CatalogReleaseError(f"catalog path cannot be represented safely in USTAR: {relative}") from exc
            files.append(
                CatalogFile(
                    relative=relative,
                    path=path,
                    size=metadata.st_size,
                    device=metadata.st_dev,
                    inode=metadata.st_ino,
                    modified_ns=metadata.st_mtime_ns,
                )
            )
            if len(files) > MAX_ARCHIVE_MEMBERS:
                raise CatalogReleaseError("catalog has too many files")
            aggregate_bytes += metadata.st_size
            estimated_tar_bytes += TAR_BLOCK_BYTES + (
                (metadata.st_size + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES
            ) * TAR_BLOCK_BYTES
            if (
                aggregate_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES
                or estimated_tar_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES
            ):
                raise CatalogReleaseError("catalog exceeds the release archive byte limit")

    visit(root, ())
    if not files:
        raise CatalogReleaseError("catalog directory is empty")
    return root, files


def _source_identity(files: list[CatalogFile]) -> CatalogIdentity:
    file_map = {item.relative: item for item in files}
    manifest = file_map.get("manifest.json")
    if manifest is None:
        raise CatalogReleaseError("catalog manifest.json is missing")
    manifest_payload = _read_private_file(
        manifest.path,
        limit=MAX_MANIFEST_BYTES,
        context="catalog manifest",
    )
    preliminary = _load_manifest_identity(manifest_payload)
    with _projection_ledger() as ledger:
        state = CatalogValidationState(expected_records=preliminary.record_count, ledger=ledger)
        members: dict[str, MemberInspection] = {}
        payloads: dict[str, bytes] = {}
        for relative, item in file_map.items():
            payload = _read_private_file(
                item.path,
                limit=(
                    MAX_SHARD_COMPRESSED_BYTES
                    if relative.startswith("shards/")
                    else MAX_MEMBER_BYTES
                ),
                context=f"catalog member {relative}",
            )
            member, retained = _inspect_catalog_member(relative, payload, state=state)
            members[relative] = member
            if retained is not None:
                payloads[relative] = retained
        return _load_manifest_identity(
            manifest_payload,
            members=members,
            payloads=payloads,
            state=state,
        )


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CatalogReleaseError(f"cannot open directory for durable sync {path}: {exc}") from exc
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise CatalogReleaseError(f"cannot durably sync directory {path}: {exc}") from exc
    finally:
        os.close(descriptor)


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _ensure_safe_directory(
    path: Path,
    *,
    parents: bool,
    context: str,
) -> tuple[int, int]:
    _reject_reparse_components(path, include_leaf=True)
    try:
        path.mkdir(parents=parents, exist_ok=True)
        _reject_reparse_components(path, include_leaf=True)
        metadata = os.lstat(path)
    except (OSError, CatalogReleaseError) as exc:
        if isinstance(exc, CatalogReleaseError):
            raise
        raise CatalogReleaseError(f"cannot prepare {context} {path}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or _stat_is_reparse(metadata):
        raise CatalogReleaseError(f"{context} is not a safe directory: {path}")
    return _directory_identity(metadata)


@contextmanager
def _bind_safe_directory(
    path: Path,
    *,
    expected_identity: tuple[int, int],
    context: str,
) -> Iterator[int]:
    """Bind installation to one verified directory object across the final rename."""

    _reject_reparse_components(path, include_leaf=True)
    descriptor = -1
    try:
        if os.name == "nt":
            import ctypes
            import msvcrt
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_file = kernel32.CreateFileW
            create_file.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            create_file.restype = wintypes.HANDLE
            handle = create_file(
                str(path),
                0,
                0x00000001 | 0x00000002,
                None,
                3,
                0x02000000 | 0x00200000,
                None,
            )
            if handle == wintypes.HANDLE(-1).value:
                raise OSError(ctypes.get_last_error(), f"cannot bind {context}")
            try:
                descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY)
            except Exception:
                kernel32.CloseHandle(handle)
                raise
        else:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _stat_is_reparse(opened)
            or _directory_identity(opened) != expected_identity
        ):
            raise CatalogReleaseError(f"{context} changed before immutable installation")
        yield descriptor
    except (OSError, CatalogReleaseError) as exc:
        if isinstance(exc, CatalogReleaseError):
            raise
        raise CatalogReleaseError(f"cannot bind {context} {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_deterministic_blob(files: list[CatalogFile], destination: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".catalog-blob-", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as raw:
            descriptor = -1
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w|",
                    format=tarfile.USTAR_FORMAT,
                    encoding="utf-8",
                    errors="strict",
                ) as archive:
                    for item in files:
                        with _open_private_regular(item.path, context=f"catalog member {item.relative}") as source:
                            before = os.fstat(source.fileno())
                            observed = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                            expected = (item.device, item.inode, item.size, item.modified_ns)
                            if observed != expected:
                                raise CatalogReleaseError(
                                    f"catalog member changed before it was packaged: {item.relative}"
                                )
                            member = tarfile.TarInfo(item.relative)
                            member.size = item.size
                            member.mode = 0o644
                            member.mtime = 0
                            member.uid = 0
                            member.gid = 0
                            member.uname = ""
                            member.gname = ""
                            archive.addfile(member, source)
                            after = os.fstat(source.fileno())
                            if observed != (
                                after.st_dev,
                                after.st_ino,
                                after.st_size,
                                after.st_mtime_ns,
                            ):
                                raise CatalogReleaseError(
                                    f"catalog member changed while it was packaged: {item.relative}"
                                )
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def _install_content_addressed(
    temporary: Path,
    destination: Path,
    digest: str,
    size: int,
    *,
    parent_identity: tuple[int, int],
) -> None:
    with _bind_safe_directory(
        destination.parent,
        expected_identity=parent_identity,
        context="immutable release store",
    ) as directory_descriptor:
        if destination.exists():
            existing_digest, existing_size = _sha256_private_file(
                destination,
                limit=MAX_BLOB_BYTES,
                context="existing immutable object",
            )
            if (existing_digest, existing_size) != (digest, size):
                raise CatalogReleaseError(
                    f"content-addressed path contains different bytes: {destination}"
                )
            temporary.unlink(missing_ok=True)
            return
        try:
            if os.name == "nt":
                os.replace(temporary, destination)
            else:
                os.replace(
                    temporary.name,
                    destination.name,
                    src_dir_fd=directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                )
                os.fsync(directory_descriptor)
            current = os.lstat(destination.parent)
            if (
                _stat_is_reparse(current)
                or _directory_identity(current) != parent_identity
            ):
                raise CatalogReleaseError(
                    "immutable release store moved during content-addressed installation"
                )
            _fsync_directory(destination.parent)
        except CatalogReleaseError:
            raise
        except OSError as exc:
            raise CatalogReleaseError(
                f"cannot install immutable release object {destination}: {exc}"
            ) from exc


def _atomic_write_immutable(
    path: Path,
    payload: bytes,
    digest: str,
    *,
    parent_identity: tuple[int, int],
) -> None:
    if path.exists():
        existing = _read_private_file(path, limit=MAX_DESCRIPTOR_BYTES, context="immutable descriptor")
        if existing != payload or hashlib.sha256(existing).hexdigest() != digest:
            raise CatalogReleaseError(f"content-addressed path contains different bytes: {path}")
        return
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _install_content_addressed(
            temporary,
            path,
            digest,
            len(payload),
            parent_identity=parent_identity,
        )
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _validate_descriptor_object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _DESCRIPTOR_KEYS:
        raise CatalogReleaseError("release descriptor has an invalid schema")
    if (
        value.get("schema") != RELEASE_SCHEMA
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != RELEASE_SCHEMA_VERSION
    ):
        raise CatalogReleaseError("unsupported release descriptor schema")
    record_count = value.get("record_count")
    blob_size = value.get("blob_size")
    if type(record_count) is not int or not 0 <= record_count <= MAX_CATALOG_RECORDS:
        raise CatalogReleaseError("release record_count is invalid")
    if type(blob_size) is not int or not 0 < blob_size <= MAX_BLOB_BYTES:
        raise CatalogReleaseError("release blob_size is invalid")
    if value.get("blob_media_type") != BLOB_MEDIA_TYPE:
        raise CatalogReleaseError("release blob media type is unsupported")
    _valid_digest(value.get("shard_set_sha256"), field="shard_set_sha256")
    _valid_digest(value.get("manifest_sha256"), field="manifest_sha256")
    _valid_digest(value.get("blob_sha256"), field="blob_sha256")
    _valid_digest(
        value.get("previous_release_sha256"),
        field="previous_release_sha256",
        allow_none=True,
    )
    return value


def descriptor_sha256(descriptor: dict[str, Any]) -> str:
    _validate_descriptor_object(descriptor)
    return hashlib.sha256(_canonical_json_bytes(descriptor)).hexdigest()


def load_descriptor(
    path: Path,
    *,
    expected_descriptor_sha256: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Load one canonical descriptor and bind it to an optional trusted digest."""

    expected = _valid_digest(
        expected_descriptor_sha256,
        field="expected_descriptor_sha256",
        allow_none=True,
    )
    payload = _read_private_file(
        Path(path),
        limit=MAX_DESCRIPTOR_BYTES,
        context="release descriptor",
    )
    actual = hashlib.sha256(payload).hexdigest()
    if expected is not None and actual != expected:
        raise CatalogReleaseError("release descriptor SHA-256 does not match the expected digest")
    value = _validate_descriptor_object(_strict_json(payload, context="release descriptor"))
    if payload != _canonical_json_bytes(value):
        raise CatalogReleaseError("release descriptor is not canonical JSON")
    return value, actual


def _copy_verified_blob(blob_path: Path, descriptor: dict[str, Any]) -> BinaryIO:
    verified = tempfile.TemporaryFile(mode="w+b")
    digest = hashlib.sha256()
    size = 0
    try:
        with _open_private_regular(Path(blob_path), context="release blob") as source:
            declared = os.fstat(source.fileno()).st_size
            if declared != descriptor["blob_size"] or declared > MAX_BLOB_BYTES:
                raise CatalogReleaseError("release blob size does not match its descriptor")
            while chunk := source.read(COPY_CHUNK_BYTES):
                size += len(chunk)
                if size > MAX_BLOB_BYTES or size > descriptor["blob_size"]:
                    raise CatalogReleaseError("release blob exceeds its declared byte limit")
                digest.update(chunk)
                verified.write(chunk)
        if size != descriptor["blob_size"]:
            raise CatalogReleaseError("release blob size does not match its descriptor")
        if digest.hexdigest() != descriptor["blob_sha256"]:
            raise CatalogReleaseError("release blob SHA-256 does not match its descriptor")
        verified.seek(0)
        return verified
    except Exception:
        verified.close()
        raise


def _bounded_decompress_blob(compressed: BinaryIO) -> BinaryIO:
    uncompressed = tempfile.TemporaryFile(mode="w+b")
    expanded = 0
    try:
        with gzip.GzipFile(fileobj=compressed, mode="rb") as stream:
            while chunk := stream.read(COPY_CHUNK_BYTES):
                expanded += len(chunk)
                if expanded > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                    raise CatalogReleaseError("release gzip expands beyond its byte limit")
                uncompressed.write(chunk)
    except CatalogReleaseError:
        uncompressed.close()
        raise
    except (gzip.BadGzipFile, EOFError, OSError, zlib.error) as exc:
        uncompressed.close()
        raise CatalogReleaseError(f"invalid release gzip stream: {exc}") from exc
    if expanded < TAR_BLOCK_BYTES * TAR_END_BLOCKS:
        uncompressed.close()
        raise CatalogReleaseError("release gzip contains an incomplete tar stream")
    uncompressed.seek(0)
    return uncompressed


def _read_exact(stream: BinaryIO, size: int, *, context: str) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(min(COPY_CHUNK_BYTES, remaining))
        if not chunk:
            raise CatalogReleaseError(f"truncated {context}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _tar_octal(field: bytes, *, field_name: str) -> int:
    if field and field[0] & 0x80:
        raise CatalogReleaseError(f"tar {field_name} uses unsupported base-256 encoding")
    stripped = field.rstrip(b"\0 ").lstrip(b" ")
    if not stripped:
        return 0
    if any(character not in b"01234567" for character in stripped):
        raise CatalogReleaseError(f"tar {field_name} is not canonical octal")
    return int(stripped, 8)


def _tar_text(field: bytes, *, field_name: str) -> str:
    value, separator, suffix = field.partition(b"\0")
    if separator and suffix.strip(b"\0"):
        raise CatalogReleaseError(f"tar {field_name} contains non-NUL suffix bytes")
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CatalogReleaseError(f"tar {field_name} is not valid UTF-8") from exc


def _tar_member_path(header: bytes) -> str:
    name = _tar_text(header[0:100], field_name="name")
    prefix = _tar_text(header[345:500], field_name="prefix")
    return _safe_member_path(f"{prefix}/{name}" if prefix else name)


def _validate_tar_header(header: bytes) -> tuple[str, int]:
    if len(header) != TAR_BLOCK_BYTES:
        raise CatalogReleaseError("truncated tar header")
    stored_checksum = _tar_octal(header[148:156], field_name="checksum")
    calculated_checksum = sum(header[:148]) + (32 * 8) + sum(header[156:])
    if stored_checksum != calculated_checksum:
        raise CatalogReleaseError("tar header checksum is invalid")
    if header[257:263] != b"ustar\0" or header[263:265] != b"00":
        raise CatalogReleaseError("release archive is not canonical USTAR")
    member_type = header[156:157]
    if member_type not in {tarfile.REGTYPE, tarfile.AREGTYPE}:
        raise CatalogReleaseError(
            f"release archive contains a non-regular or metadata member type: {member_type!r}"
        )
    if header[157:257].strip(b"\0"):
        raise CatalogReleaseError("regular tar member unexpectedly contains a link target")
    path = _tar_member_path(header)
    if path == HYDRATED_MARKER:
        raise CatalogReleaseError(f"release archive uses reserved metadata path: {path}")
    size = _tar_octal(header[124:136], field_name="size")
    if size > MAX_MEMBER_BYTES:
        raise CatalogReleaseError(f"release archive member exceeds its byte limit: {path}")
    return path, size


def _register_archive_member(
    path: str,
    *,
    portable_files: set[str],
    portable_directories: set[str],
) -> None:
    parts = tuple(part.casefold() for part in PurePosixPath(path).parts)
    key = "/".join(parts)
    parents = {"/".join(parts[:position]) for position in range(1, len(parts))}
    if key in portable_files or key in portable_directories or parents & portable_files:
        raise CatalogReleaseError(f"release archive path conflicts with another member: {path}")
    portable_files.add(key)
    portable_directories.update(parents)


def _scan_tar(
    stream: BinaryIO,
    *,
    destination: Path | None,
    state: CatalogValidationState,
) -> tuple[dict[str, MemberInspection], bytes, dict[str, bytes]]:
    members: dict[str, MemberInspection] = {}
    portable_files: set[str] = set()
    portable_directories: set[str] = set()
    manifest_payload: bytes | None = None
    payloads: dict[str, bytes] = {}
    aggregate = 0
    count = 0

    while True:
        header = stream.read(TAR_BLOCK_BYTES)
        if not header:
            raise CatalogReleaseError("release tar is missing its end markers")
        if len(header) != TAR_BLOCK_BYTES:
            raise CatalogReleaseError("release tar ends in a partial header")
        if header == b"\0" * TAR_BLOCK_BYTES:
            second = _read_exact(stream, TAR_BLOCK_BYTES, context="second tar end block")
            if second != b"\0" * TAR_BLOCK_BYTES:
                raise CatalogReleaseError("release tar has only one end marker")
            while trailing := stream.read(COPY_CHUNK_BYTES):
                if trailing.strip(b"\0"):
                    raise CatalogReleaseError("release tar has non-zero trailing bytes")
            break

        count += 1
        if count > MAX_ARCHIVE_MEMBERS:
            raise CatalogReleaseError("release archive has too many members")
        path, size = _validate_tar_header(header)
        _register_archive_member(
            path,
            portable_files=portable_files,
            portable_directories=portable_directories,
        )
        aggregate += size
        if aggregate > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise CatalogReleaseError("release archive member bytes exceed their aggregate limit")
        is_shard = path.startswith("shards/")
        should_buffer = is_shard or path in {
            "manifest.json",
            "index.json",
            "archetypes.json",
            "browser-index.json.gz",
            "runtime-summary.json",
            "search-indexable.json",
        } or re.fullmatch(r"indexes/\d{4}\.json\.gz", path) is not None
        if path == "manifest.json" and size > MAX_MANIFEST_BYTES:
            raise CatalogReleaseError("catalog manifest exceeds its byte limit")
        if is_shard and size > MAX_SHARD_COMPRESSED_BYTES:
            raise CatalogReleaseError(f"catalog shard exceeds its compressed byte limit: {path}")

        output: BinaryIO | None = None
        buffer: io.BytesIO | None = io.BytesIO() if should_buffer else None
        try:
            if destination is not None:
                output_path = destination.joinpath(*PurePosixPath(path).parts)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output = output_path.open("xb")
            digest = hashlib.sha256()
            remaining = size
            while remaining:
                chunk = stream.read(min(COPY_CHUNK_BYTES, remaining))
                if not chunk:
                    raise CatalogReleaseError(f"release archive member is truncated: {path}")
                remaining -= len(chunk)
                digest.update(chunk)
                if buffer is not None:
                    buffer.write(chunk)
                if output is not None:
                    output.write(chunk)
            if output is not None:
                output.flush()
                os.fsync(output.fileno())
        finally:
            if output is not None:
                output.close()
        padding = (-size) % TAR_BLOCK_BYTES
        if padding:
            padding_bytes = _read_exact(stream, padding, context=f"tar padding for {path}")
            if padding_bytes.strip(b"\0"):
                raise CatalogReleaseError(f"tar padding is non-zero for member: {path}")
        payload = buffer.getvalue() if buffer is not None else None
        if payload is None:
            member = MemberInspection(size=size, sha256=digest.hexdigest())
            retained = None
        else:
            member, retained = _inspect_catalog_member(path, payload, state=state)
            if (member.size, member.sha256) != (size, digest.hexdigest()):
                raise CatalogReleaseError(f"catalog member inspection disagrees with tar bytes: {path}")
        members[path] = member
        if retained is not None:
            payloads[path] = retained
        if path == "manifest.json" and payload is not None:
            manifest_payload = payload

    if manifest_payload is None:
        raise CatalogReleaseError("release archive is missing manifest.json")
    return members, manifest_payload, payloads


def _validate_catalog_members(
    members: dict[str, MemberInspection],
    manifest_payload: bytes,
    payloads: dict[str, bytes],
    descriptor: dict[str, Any],
    state: CatalogValidationState,
) -> CatalogIdentity:
    identity = _load_manifest_identity(
        manifest_payload,
        members=members,
        payloads=payloads,
        state=state,
    )
    if identity.record_count != descriptor["record_count"]:
        raise CatalogReleaseError("bundled catalog record count does not match its release descriptor")
    if identity.shard_set_sha256 != descriptor["shard_set_sha256"]:
        raise CatalogReleaseError("bundled shard-set identity does not match its release descriptor")
    if identity.manifest_sha256 != descriptor["manifest_sha256"]:
        raise CatalogReleaseError("bundled manifest SHA-256 does not match its release descriptor")
    return identity


def _validated(identity: CatalogIdentity, digest: str, *, retained_backup: Path | None = None) -> ValidatedRelease:
    return ValidatedRelease(
        descriptor_sha256=digest,
        record_count=identity.record_count,
        shard_set_sha256=identity.shard_set_sha256,
        manifest_sha256=identity.manifest_sha256,
        retained_backup=retained_backup,
    )


def _with_retained_backup(
    validated: ValidatedRelease,
    retained_backup: Path | None,
) -> ValidatedRelease:
    return ValidatedRelease(
        descriptor_sha256=validated.descriptor_sha256,
        record_count=validated.record_count,
        shard_set_sha256=validated.shard_set_sha256,
        manifest_sha256=validated.manifest_sha256,
        retained_backup=retained_backup,
    )


def _validate_blob(
    blob_path: Path,
    descriptor: dict[str, Any],
    descriptor_digest: str,
    *,
    destination: Path | None = None,
) -> ValidatedRelease:
    compressed = _copy_verified_blob(blob_path, descriptor)
    try:
        tar_stream = _bounded_decompress_blob(compressed)
    finally:
        compressed.close()
    try:
        with _projection_ledger() as ledger:
            state = CatalogValidationState(
                expected_records=descriptor["record_count"],
                ledger=ledger,
            )
            members, manifest_payload, payloads = _scan_tar(
                tar_stream,
                destination=destination,
                state=state,
            )
            identity = _validate_catalog_members(
                members,
                manifest_payload,
                payloads,
                descriptor,
                state,
            )
    finally:
        tar_stream.close()
    return _validated(identity, descriptor_digest)


def package_catalog(
    catalog_dir: Path,
    output_dir: Path,
    *,
    previous_release_sha256: str | None = None,
) -> PackageResult:
    previous = _valid_digest(
        previous_release_sha256,
        field="previous_release_sha256",
        allow_none=True,
    )
    catalog_root, files = _catalog_files(Path(catalog_dir))
    identity = _source_identity(files)
    requested_output = Path(output_dir)
    _reject_reparse_components(requested_output, include_leaf=True)
    output_root = Path(os.path.abspath(requested_output))
    if output_root == catalog_root or catalog_root in output_root.parents:
        raise CatalogReleaseError("release output cannot be inside the source catalog")
    _ensure_safe_directory(output_root, parents=True, context="release output root")
    blob_namespace = output_root / "blobs"
    blob_root = output_root / "blobs" / "sha256"
    descriptor_namespace = output_root / "releases"
    descriptor_root = output_root / "releases" / "sha256"
    for directory, context in (
        (blob_namespace, "release blob namespace"),
        (blob_root, "release blob store"),
        (descriptor_namespace, "release descriptor namespace"),
        (descriptor_root, "release descriptor store"),
    ):
        _ensure_safe_directory(directory, parents=False, context=context)

    blob_store_identity = _ensure_safe_directory(
        blob_root,
        parents=False,
        context="release blob store",
    )
    temporary_blob = blob_root / f".building-{uuid.uuid4().hex}"
    _write_deterministic_blob(files, temporary_blob)
    try:
        blob_sha256, blob_size = _sha256_private_file(
            temporary_blob,
            limit=MAX_BLOB_BYTES,
            context="completed release blob",
        )
        descriptor: dict[str, Any] = {
            "schema": RELEASE_SCHEMA,
            "schema_version": RELEASE_SCHEMA_VERSION,
            "record_count": identity.record_count,
            "shard_set_sha256": identity.shard_set_sha256,
            "manifest_sha256": identity.manifest_sha256,
            "blob_media_type": BLOB_MEDIA_TYPE,
            "blob_sha256": blob_sha256,
            "blob_size": blob_size,
            "previous_release_sha256": previous,
        }
        _validate_descriptor_object(descriptor)
        descriptor_payload = _canonical_json_bytes(descriptor)
        release_sha256 = hashlib.sha256(descriptor_payload).hexdigest()
        _validate_blob(temporary_blob, descriptor, release_sha256)
        blob_path = blob_root / blob_sha256
        _install_content_addressed(
            temporary_blob,
            blob_path,
            blob_sha256,
            blob_size,
            parent_identity=blob_store_identity,
        )
    except Exception:
        temporary_blob.unlink(missing_ok=True)
        raise

    descriptor_path = descriptor_root / f"{release_sha256}.json"
    descriptor_store_identity = _ensure_safe_directory(
        descriptor_root,
        parents=False,
        context="release descriptor store",
    )
    _atomic_write_immutable(
        descriptor_path,
        descriptor_payload,
        release_sha256,
        parent_identity=descriptor_store_identity,
    )
    return PackageResult(
        descriptor_path=descriptor_path,
        blob_path=blob_path,
        descriptor_sha256=release_sha256,
        blob_sha256=blob_sha256,
        blob_size=blob_size,
    )


def validate_release(
    descriptor_path: Path,
    blob_path: Path,
    *,
    expected_descriptor_sha256: str,
) -> ValidatedRelease:
    expected = _valid_digest(
        expected_descriptor_sha256,
        field="expected_descriptor_sha256",
    )
    assert expected is not None
    descriptor, descriptor_digest = load_descriptor(
        Path(descriptor_path),
        expected_descriptor_sha256=expected,
    )
    return _validate_blob(Path(blob_path), descriptor, descriptor_digest)


def _lock_file(target: Path) -> Path:
    return target.parent / f".{target.name}.hydrate.lock"


def _journal_file(target: Path) -> Path:
    return target.parent / f".{target.name}.hydrate.journal.json"


@contextmanager
def _target_lock(target: Path) -> Iterator[None]:
    path = _lock_file(target)
    _reject_reparse_components(path, include_leaf=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
        _assert_regular_metadata(metadata, context="hydrate lock")
        if metadata.st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, CatalogReleaseError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if isinstance(exc, CatalogReleaseError):
            raise
        raise CatalogReleaseError(f"hydrate target is already locked or lock is unsafe: {exc}") from exc
    try:
        yield
    finally:
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _write_atomic_file(path: Path, payload: bytes, *, limit: int, context: str) -> None:
    if not 0 < len(payload) <= limit:
        raise CatalogReleaseError(f"{context} exceeds its byte limit")
    if path.exists():
        metadata = os.lstat(path)
        _assert_regular_metadata(metadata, context=f"existing {context}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _journal_payload(
    target: Path,
    *,
    staging: Path,
    backup: Path | None,
    descriptor_digest: str,
    phase: str,
) -> dict[str, Any]:
    if phase not in _JOURNAL_PHASES:
        raise CatalogReleaseError(f"invalid hydration journal phase: {phase}")
    return {
        "schema": JOURNAL_SCHEMA,
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "target_name": target.name,
        "staging_name": staging.name,
        "backup_name": backup.name if backup is not None else None,
        "descriptor_sha256": descriptor_digest,
        "phase": phase,
    }


def _write_journal(
    target: Path,
    *,
    staging: Path,
    backup: Path | None,
    descriptor_digest: str,
    phase: str,
) -> None:
    payload = _journal_payload(
        target,
        staging=staging,
        backup=backup,
        descriptor_digest=descriptor_digest,
        phase=phase,
    )
    _write_atomic_file(
        _journal_file(target),
        _canonical_json_bytes(payload),
        limit=MAX_JOURNAL_BYTES,
        context="hydration journal",
    )


def _owned_sibling(target: Path, name: object, *, kind: str) -> Path | None:
    if name is None:
        return None
    if not isinstance(name, str):
        raise CatalogReleaseError(f"hydration journal {kind} name is invalid")
    prefix = f".{target.name}.{'hydrate' if kind == 'staging' else 'previous'}-"
    token = name.removeprefix(prefix)
    if not name.startswith(prefix) or OWNED_TOKEN_RE.fullmatch(token) is None:
        raise CatalogReleaseError(f"hydration journal {kind} name is unsafe")
    path = target.parent / name
    if path.parent != target.parent:
        raise CatalogReleaseError(f"hydration journal {kind} escapes target parent")
    return path


def _load_journal(target: Path) -> tuple[dict[str, Any], Path, Path | None] | None:
    path = _journal_file(target)
    if not path.exists():
        return None
    payload = _read_private_file(path, limit=MAX_JOURNAL_BYTES, context="hydration journal")
    value = _strict_json(payload, context="hydration journal")
    if not isinstance(value, dict) or set(value) != _JOURNAL_KEYS:
        raise CatalogReleaseError("hydration journal schema is invalid")
    if (
        value.get("schema") != JOURNAL_SCHEMA
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != JOURNAL_SCHEMA_VERSION
        or value.get("target_name") != target.name
        or value.get("phase") not in _JOURNAL_PHASES
    ):
        raise CatalogReleaseError("hydration journal identity is invalid")
    _valid_digest(value.get("descriptor_sha256"), field="journal descriptor_sha256")
    staging = _owned_sibling(target, value.get("staging_name"), kind="staging")
    backup = _owned_sibling(target, value.get("backup_name"), kind="backup")
    if staging is None:
        raise CatalogReleaseError("hydration journal staging path is missing")
    if payload != _canonical_json_bytes(value):
        raise CatalogReleaseError("hydration journal is not canonical JSON")
    return value, staging, backup


def _safe_remove_owned_tree(path: Path, *, target: Path, kind: str) -> None:
    expected = _owned_sibling(target, path.name, kind=kind)
    if expected != path:
        raise CatalogReleaseError(f"refusing to remove an unowned {kind} path: {path}")
    if not path.exists():
        return
    if _is_link_or_junction(path) or not path.is_dir():
        raise CatalogReleaseError(f"refusing to remove unsafe {kind} directory: {path}")

    def inspect(directory: Path) -> None:
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise CatalogReleaseError(f"cannot inspect {kind} directory before cleanup: {exc}") from exc
        for entry in entries:
            child = Path(entry.path)
            if _is_link_or_junction(child):
                raise CatalogReleaseError(f"refusing to remove {kind} tree containing a reparse point: {child}")
            metadata = os.lstat(child)
            if stat.S_ISDIR(metadata.st_mode):
                inspect(child)
            else:
                _assert_regular_metadata(metadata, context=f"{kind} cleanup member")

    inspect(path)
    try:
        shutil.rmtree(path)
        _fsync_directory(path.parent)
    except OSError as exc:
        raise CatalogReleaseError(f"cannot remove verified {kind} directory: {exc}") from exc


def _unlink_private(path: Path, *, context: str) -> None:
    if not path.exists():
        return
    with _open_private_regular(path, context=context):
        pass
    try:
        path.unlink()
        _fsync_directory(path.parent)
    except OSError as exc:
        raise CatalogReleaseError(f"cannot remove {context}: {exc}") from exc


def _marker_payload(descriptor_digest: str) -> bytes:
    return _canonical_json_bytes(
        {
            "schema": RELEASE_SCHEMA,
            "schema_version": RELEASE_SCHEMA_VERSION,
            "descriptor_sha256": descriptor_digest,
        }
    )


def _target_matches_release(target: Path, descriptor_digest: str) -> bool:
    if not target.exists() or _is_link_or_junction(target) or not target.is_dir():
        return False
    marker = target / HYDRATED_MARKER
    if not marker.exists():
        return False
    try:
        return _read_private_file(marker, limit=MAX_DESCRIPTOR_BYTES, context="hydrated release marker") == _marker_payload(
            descriptor_digest
        )
    except CatalogReleaseError:
        return False


def _recover_hydration(target: Path) -> None:
    loaded = _load_journal(target)
    if loaded is None:
        return
    journal, staging, backup = loaded
    digest = str(journal["descriptor_sha256"])
    target_exists = target.exists()
    target_matches = _target_matches_release(target, digest)
    backup_exists = backup is not None and backup.exists()

    if target_matches:
        if staging.exists():
            _safe_remove_owned_tree(staging, target=target, kind="staging")
        if backup_exists and backup is not None:
            _safe_remove_owned_tree(backup, target=target, kind="backup")
        _unlink_private(_journal_file(target), context="hydration journal")
        return

    if backup_exists and not target_exists and backup is not None:
        try:
            os.replace(backup, target)
            _fsync_directory(target.parent)
        except OSError as exc:
            raise CatalogReleaseError(f"cannot restore prior catalog from recovery journal: {exc}") from exc
        if staging.exists():
            _safe_remove_owned_tree(staging, target=target, kind="staging")
        _unlink_private(_journal_file(target), context="hydration journal")
        return

    if not backup_exists and journal["phase"] in {"prepared", "switching", "old_moved"}:
        if staging.exists():
            _safe_remove_owned_tree(staging, target=target, kind="staging")
        _unlink_private(_journal_file(target), context="hydration journal")
        return

    raise CatalogReleaseError(
        "hydration journal describes an ambiguous interrupted commit; preserving target, staging, and backup"
    )


def hydrate_release(
    descriptor_path: Path,
    blob_path: Path,
    target_dir: Path,
    *,
    expected_descriptor_sha256: str,
) -> ValidatedRelease:
    """Validate and recoverably replace a catalog target under an exclusive lock."""

    expected = _valid_digest(
        expected_descriptor_sha256,
        field="expected_descriptor_sha256",
    )
    assert expected is not None
    descriptor, descriptor_digest = load_descriptor(
        Path(descriptor_path),
        expected_descriptor_sha256=expected,
    )
    requested_target = Path(target_dir)
    _reject_reparse_components(requested_target, include_leaf=True)
    target = requested_target.resolve(strict=False)
    if target == target.parent:
        raise CatalogReleaseError("hydrate target cannot be a filesystem root")
    target.parent.mkdir(parents=True, exist_ok=True)
    if _is_link_or_junction(target.parent) or not target.parent.is_dir():
        raise CatalogReleaseError(f"hydrate parent is not a safe directory: {target.parent}")
    if target.exists() and (_is_link_or_junction(target) or not target.is_dir()):
        raise CatalogReleaseError(f"hydrate target is not a safe directory: {target}")

    with _target_lock(target):
        _recover_hydration(target)
        token = uuid.uuid4().hex
        staging = target.parent / f".{target.name}.hydrate-{token}"
        backup = target.parent / f".{target.name}.previous-{token}" if target.exists() else None
        _write_journal(
            target,
            staging=staging,
            backup=backup,
            descriptor_digest=descriptor_digest,
            phase="prepared",
        )
        validated: ValidatedRelease | None = None
        try:
            staging.mkdir()
            _fsync_directory(target.parent)
            validated = _validate_blob(
                Path(blob_path),
                descriptor,
                descriptor_digest,
                destination=staging,
            )
            _write_atomic_file(
                staging / HYDRATED_MARKER,
                _marker_payload(descriptor_digest),
                limit=MAX_DESCRIPTOR_BYTES,
                context="hydrated release marker",
            )
            _write_journal(
                target,
                staging=staging,
                backup=backup,
                descriptor_digest=descriptor_digest,
                phase="switching",
            )
            if backup is not None:
                os.replace(target, backup)
                _fsync_directory(target.parent)
            _write_journal(
                target,
                staging=staging,
                backup=backup,
                descriptor_digest=descriptor_digest,
                phase="old_moved",
            )
            os.replace(staging, target)
            _fsync_directory(target.parent)
            _write_journal(
                target,
                staging=staging,
                backup=backup,
                descriptor_digest=descriptor_digest,
                phase="committed",
            )
        except Exception as exc:
            committed = validated is not None and _target_matches_release(
                target,
                descriptor_digest,
            )
            try:
                _recover_hydration(target)
            except CatalogReleaseError as recovery_exc:
                if committed and _target_matches_release(target, descriptor_digest):
                    retained = backup if backup is not None and backup.exists() else None
                    return _with_retained_backup(validated, retained)
                raise CatalogReleaseError(
                    f"catalog hydration failed ({exc}); automatic recovery also failed ({recovery_exc})"
                ) from exc
            if committed:
                return _with_retained_backup(validated, None)
            if isinstance(exc, CatalogReleaseError):
                raise
            raise CatalogReleaseError(f"cannot commit hydrated catalog: {exc}") from exc

        retained_backup: Path | None = None
        if backup is not None and backup.exists():
            try:
                _safe_remove_owned_tree(backup, target=target, kind="backup")
            except CatalogReleaseError:
                retained_backup = backup
                try:
                    _write_journal(
                        target,
                        staging=staging,
                        backup=backup,
                        descriptor_digest=descriptor_digest,
                        phase="cleanup_pending",
                    )
                except CatalogReleaseError:
                    if not _target_matches_release(target, descriptor_digest):
                        raise
        if retained_backup is None:
            try:
                _unlink_private(_journal_file(target), context="hydration journal")
            except CatalogReleaseError:
                if not _target_matches_release(target, descriptor_digest):
                    raise
        assert validated is not None
        return _with_retained_backup(validated, retained_backup)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Package, validate, or hydrate an immutable CVE catalog release."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    package = commands.add_parser("package", help="package a catalog into immutable release objects")
    package.add_argument("--catalog", type=Path, required=True)
    package.add_argument("--output", type=Path, required=True)
    package.add_argument("--previous-release-sha256")
    validate = commands.add_parser("validate", help="validate a descriptor and release blob")
    validate.add_argument("--descriptor", type=Path, required=True)
    validate.add_argument("--blob", type=Path, required=True)
    validate.add_argument("--expected-descriptor-sha256", required=True)
    hydrate = commands.add_parser("hydrate", help="recoverably hydrate a release into a directory")
    hydrate.add_argument("--descriptor", type=Path, required=True)
    hydrate.add_argument("--blob", type=Path, required=True)
    hydrate.add_argument("--target", type=Path, required=True)
    hydrate.add_argument("--expected-descriptor-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "package":
            result = package_catalog(
                args.catalog,
                args.output,
                previous_release_sha256=args.previous_release_sha256,
            )
            payload = {
                "descriptor_path": str(result.descriptor_path),
                "blob_path": str(result.blob_path),
                "descriptor_sha256": result.descriptor_sha256,
                "blob_sha256": result.blob_sha256,
                "blob_size": result.blob_size,
            }
        elif args.command == "validate":
            validated = validate_release(
                args.descriptor,
                args.blob,
                expected_descriptor_sha256=args.expected_descriptor_sha256,
            )
            payload = {
                "descriptor_sha256": validated.descriptor_sha256,
                "record_count": validated.record_count,
                "shard_set_sha256": validated.shard_set_sha256,
            }
        else:
            validated = hydrate_release(
                args.descriptor,
                args.blob,
                args.target,
                expected_descriptor_sha256=args.expected_descriptor_sha256,
            )
            payload = {
                "descriptor_sha256": validated.descriptor_sha256,
                "record_count": validated.record_count,
                "shard_set_sha256": validated.shard_set_sha256,
                "target": str(args.target.resolve()),
                "retained_backup": (
                    str(validated.retained_backup) if validated.retained_backup is not None else None
                ),
            }
    except CatalogReleaseError as exc:
        print(f"catalog release error: {exc}", file=sys.stderr)
        return 2
    print(_canonical_json_bytes(payload).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
