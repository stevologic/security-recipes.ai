#!/usr/bin/env python3
"""Bounded, read-only SQLite/FTS5 search for the generated CVE catalog."""

from __future__ import annotations

import hashlib
import math
import os
import re
import sqlite3
import stat
import time
from datetime import date, datetime
from pathlib import Path
from typing import Any, TypedDict


APPLICATION_ID = 0x43564553  # "CVES"
DATABASE_SCHEMA_VERSION = 1
MANIFEST_SCHEMA_VERSION = 2

MAX_DATABASE_BYTES = 8 * 1024 * 1024 * 1024
MAX_CATALOG_RECORDS = 1_000_000
MAX_SHARDS = 100_000
MAX_QUERY_LENGTH = 120
MAX_QUERY_TERMS = 8
MAX_QUERY_TERM_LENGTH = 64
MAX_RESULTS = 100
DEFAULT_QUERY_TIMEOUT_SECONDS = 2.0
MAX_QUERY_TIMEOUT_SECONDS = 10.0
DEFAULT_VALIDATION_TIMEOUT_SECONDS = 15.0
PROGRESS_HANDLER_STEPS = 100

SHA256_RE = re.compile(r"[0-9a-f]{64}")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CVE_CANONICAL_RE = re.compile(r"CVE-(\d{4})-(\d{4,})")
CVE_PREFIX_RE = re.compile(r"CVE-\d{4}(?:-\d*)?", re.IGNORECASE)
TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)
CATALOG_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
SHARD_PATH_RE = re.compile(r"shards/\d{4}/\d{4,}\.jsonl\.gz")

EXPECTED_METADATA_KEYS = frozenset(
    {
        "catalog_updated_at",
        "database_schema_version",
        "fts_columns",
        "manifest_schema_version",
        "manifest_sha256",
        "record_count",
        "shard_count",
        "shard_set_sha256",
    }
)
EXPECTED_FTS_COLUMNS = "cve,title,summary,ecosystem,archetypes,products"
EXPECTED_METADATA_SCHEMA_SQL = """
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID
"""
EXPECTED_CVES_SCHEMA_SQL = """
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
)
"""
EXPECTED_CVE_COLUMNS = (
    "id",
    "cve",
    "title",
    "summary",
    "ecosystem",
    "archetypes",
    "products",
    "severity",
    "severity_rank",
    "score",
    "published",
    "publication_year",
    "kev",
    "has_markdown",
    "shard_path",
)
EXPECTED_FTS_TABLE_COLUMNS = (
    "cve",
    "title",
    "summary",
    "ecosystem",
    "archetypes",
    "products",
)
EXPECTED_CVE_COLUMN_TYPES = (
    "INTEGER",
    "TEXT",
    "TEXT",
    "TEXT",
    "TEXT",
    "TEXT",
    "TEXT",
    "TEXT",
    "INTEGER",
    "REAL",
    "TEXT",
    "INTEGER",
    "INTEGER",
    "INTEGER",
    "TEXT",
)
EXPECTED_INDEX_COLUMNS = {
    "cves_newest_idx": (("published", 1), ("cve", 1)),
    "cves_severity_newest_idx": (("severity", 0), ("published", 1), ("cve", 1)),
    "cves_year_newest_idx": (("publication_year", 0), ("published", 1), ("cve", 1)),
    "cves_kev_newest_idx": (("kev", 0), ("published", 1), ("cve", 1)),
    "cves_filter_newest_idx": (
        ("severity", 0),
        ("publication_year", 0),
        ("kev", 0),
        ("published", 1),
        ("cve", 1),
    ),
}


class CVESearchRuntimeError(RuntimeError):
    """Base exception for the bounded CVE search runtime."""


class CVESearchDatabaseError(CVESearchRuntimeError):
    """The configured search database cannot be trusted or queried safely."""


class CVESearchQueryError(CVESearchRuntimeError, ValueError):
    """A caller supplied a search request outside the bounded query policy."""


class CVESearchTimeoutError(CVESearchRuntimeError, TimeoutError):
    """SQLite cancelled a search after its monotonic deadline elapsed."""


class CVESearchPage(TypedDict):
    """JSON-ready bounded search response."""

    results: list[dict[str, Any]]
    total_matches: int
    truncated: bool


def _is_link_or_junction(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction and is_junction())
    except OSError:
        return True


def _reject_link_components(path: Path) -> None:
    candidate = path
    while True:
        if _is_link_or_junction(candidate):
            raise CVESearchDatabaseError("CVE search database paths must not contain links or junctions")
        if candidate.parent == candidate:
            return
        candidate = candidate.parent


def _validated_sha256(value: object, field: str) -> str:
    digest = str(value or "").strip().lower()
    if SHA256_RE.fullmatch(digest) is None:
        raise CVESearchDatabaseError(f"{field} must be a 64-character SHA-256 digest")
    return digest


def _validated_int(value: object, field: str, *, minimum: int, maximum: int) -> int:
    if type(value) is int:
        number = value
    elif isinstance(value, str) and re.fullmatch(r"0|[1-9]\d*", value):
        number = int(value)
    else:
        raise CVESearchDatabaseError(f"{field} must be an integer")
    if not minimum <= number <= maximum:
        raise CVESearchDatabaseError(f"{field} is outside the supported range")
    return number


def _normalized_schema_sql(value: str) -> str:
    return re.sub(r"\s+", "", value.casefold()).removesuffix(";")


class CVESearchRuntime:
    """Open and query one immutable CVE FTS database without loading its corpus.

    Every connection uses SQLite URI read-only and immutable modes. The expected
    revision, manifest digest, record count, and whole-file database digest must
    come from independently validated deployment configuration. The database
    digest cannot safely be read from the database that it authenticates.
    """

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        expected_revision: str,
        expected_record_count: int,
        expected_manifest_sha256: str,
        expected_database_sha256: str,
        max_database_bytes: int = MAX_DATABASE_BYTES,
        query_timeout_seconds: float = DEFAULT_QUERY_TIMEOUT_SECONDS,
        validation_timeout_seconds: float = DEFAULT_VALIDATION_TIMEOUT_SECONDS,
    ) -> None:
        configured_path = Path(database_path).expanduser().absolute()
        _reject_link_components(configured_path)
        try:
            resolved_path = configured_path.resolve(strict=True)
            file_status = resolved_path.stat(follow_symlinks=False)
        except (OSError, RuntimeError) as exc:
            raise CVESearchDatabaseError("CVE search database is missing or inaccessible") from exc
        if not stat.S_ISREG(file_status.st_mode):
            raise CVESearchDatabaseError("CVE search database must be a regular file")
        if type(max_database_bytes) is not int or not 1 <= max_database_bytes <= MAX_DATABASE_BYTES:
            raise CVESearchDatabaseError("max_database_bytes is outside the supported range")
        if not 0 < file_status.st_size <= max_database_bytes:
            raise CVESearchDatabaseError("CVE search database is empty or exceeds the configured size limit")

        self._database_path = resolved_path
        self._database_uri = resolved_path.as_uri() + "?mode=ro&immutable=1"
        self._maximum_database_bytes = max_database_bytes
        self._expected_revision = _validated_sha256(expected_revision, "expected_revision")
        self._expected_manifest_sha256 = _validated_sha256(
            expected_manifest_sha256,
            "expected_manifest_sha256",
        )
        self._expected_database_sha256 = _validated_sha256(
            expected_database_sha256,
            "expected_database_sha256",
        )
        self._expected_record_count = _validated_int(
            expected_record_count,
            "expected_record_count",
            minimum=0,
            maximum=MAX_CATALOG_RECORDS,
        )
        self._query_timeout_seconds = self._validated_timeout(
            query_timeout_seconds,
            "query_timeout_seconds",
            maximum=MAX_QUERY_TIMEOUT_SECONDS,
        )
        validation_timeout = self._validated_timeout(
            validation_timeout_seconds,
            "validation_timeout_seconds",
            maximum=60.0,
        )
        self._clock = time.monotonic
        self._file_identity = self._file_fingerprint(file_status)
        validation_deadline = self._clock() + validation_timeout
        if self._database_sha256(validation_deadline) != self._expected_database_sha256:
            raise CVESearchDatabaseError("CVE search database digest does not match deployment configuration")
        self._metadata = self._validate_database(validation_deadline)

    @staticmethod
    def _validated_timeout(value: object, field: str, *, maximum: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise CVESearchDatabaseError(f"{field} must be a finite number")
        timeout = float(value)
        if not math.isfinite(timeout) or not 0 < timeout <= maximum:
            raise CVESearchDatabaseError(f"{field} is outside the supported range")
        return timeout

    @staticmethod
    def _file_fingerprint(file_status: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            int(file_status.st_dev),
            int(file_status.st_ino),
            int(file_status.st_size),
            int(file_status.st_mtime_ns),
            int(file_status.st_ctime_ns),
        )

    def _assert_file_unchanged(self) -> None:
        _reject_link_components(self._database_path)
        try:
            file_status = self._database_path.stat(follow_symlinks=False)
        except OSError as exc:
            raise CVESearchDatabaseError("CVE search database disappeared during runtime") from exc
        if (
            not stat.S_ISREG(file_status.st_mode)
            or not 0 < file_status.st_size <= self._maximum_database_bytes
            or self._file_fingerprint(file_status) != self._file_identity
        ):
            raise CVESearchDatabaseError("CVE search database changed after validation")

    def _database_sha256(self, deadline: float) -> str:
        digest = hashlib.sha256()
        try:
            with self._database_path.open("rb", buffering=0) as stream:
                if self._file_fingerprint(os.fstat(stream.fileno())) != self._file_identity:
                    raise CVESearchDatabaseError("CVE search database changed before digest validation")
                while chunk := stream.read(1024 * 1024):
                    if self._clock() >= deadline:
                        raise CVESearchDatabaseError("CVE search database digest validation exceeded its deadline")
                    digest.update(chunk)
        except CVESearchRuntimeError:
            raise
        except OSError as exc:
            raise CVESearchDatabaseError("CVE search database could not be read for digest validation") from exc
        self._assert_file_unchanged()
        return digest.hexdigest()

    def _connect(self, deadline: float) -> sqlite3.Connection:
        self._assert_file_unchanged()
        try:
            connection = sqlite3.connect(
                self._database_uri,
                uri=True,
                timeout=0.1,
                isolation_level=None,
                check_same_thread=True,
            )
            connection.row_factory = sqlite3.Row
            try:
                connection.enable_load_extension(False)
            except (AttributeError, sqlite3.NotSupportedError):
                pass
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA cache_size = -4096")
            connection.execute("PRAGMA temp_store = MEMORY")
            connection.execute("PRAGMA mmap_size = 0")
            connection.execute("PRAGMA busy_timeout = 100")
            if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
                raise CVESearchDatabaseError("SQLite did not enable query-only mode")
            if connection.execute("PRAGMA trusted_schema").fetchone()[0] != 0:
                raise CVESearchDatabaseError("SQLite did not disable trusted-schema mode")
            connection.set_progress_handler(
                lambda: 1 if self._clock() >= deadline else 0,
                PROGRESS_HANDLER_STEPS,
            )
            self._assert_file_unchanged()
            return connection
        except CVESearchRuntimeError:
            try:
                connection.close()
            except (NameError, sqlite3.Error):
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.close()
            except (NameError, sqlite3.Error):
                pass
            raise CVESearchDatabaseError("CVE search database could not be opened safely") from exc

    @staticmethod
    def _schema_columns(connection: sqlite3.Connection, table: str) -> tuple[sqlite3.Row, ...]:
        return tuple(connection.execute(f"PRAGMA table_info('{table}')"))

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        user_version = connection.execute("PRAGMA user_version").fetchone()[0]
        if application_id != APPLICATION_ID or user_version != DATABASE_SCHEMA_VERSION:
            raise CVESearchDatabaseError("CVE search database has the wrong application or schema version")

        objects = {
            str(row[0]): (str(row[1]), str(row[2] or ""))
            for row in connection.execute(
                "SELECT name, type, sql FROM sqlite_schema WHERE name IN ('metadata', 'cves', 'cve_fts')"
            )
        }
        if objects.get("metadata", (None,))[0] != "table" or objects.get("cves", (None,))[0] != "table":
            raise CVESearchDatabaseError("CVE search database is missing required tables")
        if objects.get("cve_fts", (None,))[0] != "table":
            raise CVESearchDatabaseError("CVE search database is missing its FTS5 table")
        if _normalized_schema_sql(objects["metadata"][1]) != _normalized_schema_sql(EXPECTED_METADATA_SCHEMA_SQL):
            raise CVESearchDatabaseError("CVE search metadata declaration is invalid")
        if _normalized_schema_sql(objects["cves"][1]) != _normalized_schema_sql(EXPECTED_CVES_SCHEMA_SQL):
            raise CVESearchDatabaseError("CVE search content declaration is invalid")
        metadata_columns = self._schema_columns(connection, "metadata")
        if tuple((str(row[1]), str(row[2]), int(row[3]), int(row[5])) for row in metadata_columns) != (
            ("key", "TEXT", 1, 1),
            ("value", "TEXT", 1, 0),
        ):
            raise CVESearchDatabaseError("CVE search metadata schema is invalid")
        cve_columns = self._schema_columns(connection, "cves")
        if (
            tuple(str(row[1]) for row in cve_columns) != EXPECTED_CVE_COLUMNS
            or tuple(str(row[2]) for row in cve_columns) != EXPECTED_CVE_COLUMN_TYPES
            or tuple(int(row[3]) for row in cve_columns) != (0, *([1] * 14))
            or tuple(int(row[5]) for row in cve_columns) != (1, *([0] * 14))
        ):
            raise CVESearchDatabaseError("CVE search content schema is invalid")
        if tuple(str(row[1]) for row in self._schema_columns(connection, "cve_fts")) != EXPECTED_FTS_TABLE_COLUMNS:
            raise CVESearchDatabaseError("CVE search FTS column schema is invalid")

        fts_sql = _normalized_schema_sql(objects["cve_fts"][1])
        required_fts_fragments = (
            "createvirtualtablecve_ftsusingfts5(",
            "cve,title,summary,ecosystem,archetypes,products,",
            "content='cves'",
            "content_rowid='id'",
            "tokenize='unicode61remove_diacritics2'",
        )
        if any(fragment not in fts_sql for fragment in required_fts_fragments):
            raise CVESearchDatabaseError("CVE search FTS configuration is invalid")

        indexes = {str(row[1]) for row in connection.execute("PRAGMA index_list('cves')")}
        for index, expected_columns in EXPECTED_INDEX_COLUMNS.items():
            if index not in indexes:
                raise CVESearchDatabaseError("CVE search database is missing required indexes")
            actual_columns = tuple(
                (str(row[2]), int(row[3]))
                for row in connection.execute(f"PRAGMA index_xinfo('{index}')")
                if int(row[5]) == 1
            )
            if actual_columns != expected_columns:
                raise CVESearchDatabaseError("CVE search database index schema is invalid")

    def _validate_database(self, deadline: float) -> dict[str, str]:
        connection = self._connect(deadline)
        try:
            self._validate_schema(connection)
            metadata_rows = connection.execute("SELECT key, value FROM metadata ORDER BY key").fetchall()
            metadata = {str(row[0]): str(row[1]) for row in metadata_rows}
            if len(metadata_rows) != len(metadata) or set(metadata) != EXPECTED_METADATA_KEYS:
                raise CVESearchDatabaseError("CVE search database metadata schema is invalid")
            if metadata["database_schema_version"] != str(DATABASE_SCHEMA_VERSION):
                raise CVESearchDatabaseError("CVE search database metadata has the wrong schema version")
            if metadata["manifest_schema_version"] != str(MANIFEST_SCHEMA_VERSION):
                raise CVESearchDatabaseError("CVE search database metadata has the wrong manifest version")
            if metadata["fts_columns"] != EXPECTED_FTS_COLUMNS:
                raise CVESearchDatabaseError("CVE search database metadata has the wrong FTS columns")
            if CATALOG_TIMESTAMP_RE.fullmatch(metadata["catalog_updated_at"]) is None:
                raise CVESearchDatabaseError("CVE search database metadata has an invalid catalog timestamp")
            try:
                datetime.strptime(metadata["catalog_updated_at"], "%Y-%m-%dT%H:%M:%SZ")
            except ValueError as exc:
                raise CVESearchDatabaseError(
                    "CVE search database metadata has an invalid catalog timestamp"
                ) from exc
            metadata_revision = metadata["shard_set_sha256"]
            if SHA256_RE.fullmatch(metadata_revision) is None or metadata_revision != self._expected_revision:
                raise CVESearchDatabaseError("CVE search database revision does not match deployment configuration")
            metadata_manifest_sha256 = metadata["manifest_sha256"]
            if (
                SHA256_RE.fullmatch(metadata_manifest_sha256) is None
                or metadata_manifest_sha256 != self._expected_manifest_sha256
            ):
                raise CVESearchDatabaseError("CVE search database manifest digest does not match deployment configuration")
            metadata_count = _validated_int(
                metadata["record_count"],
                "record_count",
                minimum=0,
                maximum=MAX_CATALOG_RECORDS,
            )
            if metadata_count != self._expected_record_count:
                raise CVESearchDatabaseError("CVE search database record count does not match deployment configuration")
            shard_count = _validated_int(
                metadata["shard_count"],
                "shard_count",
                minimum=0,
                maximum=MAX_SHARDS,
            )
            if (metadata_count == 0) != (shard_count == 0):
                raise CVESearchDatabaseError("CVE search database shard metadata is inconsistent")

            actual_count = int(connection.execute("SELECT count(*) FROM cves").fetchone()[0])
            fts_count = int(connection.execute("SELECT count(*) FROM cve_fts").fetchone()[0])
            if actual_count != metadata_count or fts_count != metadata_count:
                raise CVESearchDatabaseError("CVE search database content count does not match metadata")
            docsize_count = int(connection.execute("SELECT count(*) FROM cve_fts_docsize").fetchone()[0])
            missing_docsize = connection.execute(
                "SELECT 1 FROM cves AS c LEFT JOIN cve_fts_docsize AS d ON d.id = c.id "
                "WHERE d.id IS NULL LIMIT 1"
            ).fetchone()
            unexpected_docsize = connection.execute(
                "SELECT 1 FROM cve_fts_docsize AS d LEFT JOIN cves AS c ON c.id = d.id "
                "WHERE c.id IS NULL OR length(d.sz) = 0 LIMIT 1"
            ).fetchone()
            if docsize_count != metadata_count or missing_docsize is not None or unexpected_docsize is not None:
                raise CVESearchDatabaseError("CVE search database FTS document coverage is inconsistent")
            if actual_count:
                boundary_rows = connection.execute(
                    "SELECT id, cve FROM cves WHERE id IN ((SELECT min(id) FROM cves), (SELECT max(id) FROM cves))"
                ).fetchall()
                for boundary_row in boundary_rows:
                    indexed = connection.execute(
                        "SELECT 1 FROM cve_fts WHERE cve_fts MATCH ? AND rowid = ? LIMIT 1",
                        (f'"{boundary_row[1]}"', boundary_row[0]),
                    ).fetchone()
                    if indexed is None:
                        raise CVESearchDatabaseError("CVE search database FTS index is incomplete")
            quick_check = [str(row[0]) for row in connection.execute("PRAGMA quick_check(1)")]
            if quick_check != ["ok"]:
                raise CVESearchDatabaseError("CVE search database failed SQLite's structural integrity check")
            self._assert_file_unchanged()
            return metadata
        except CVESearchRuntimeError:
            raise
        except sqlite3.OperationalError as exc:
            if "interrupted" in str(exc).casefold():
                raise CVESearchDatabaseError("CVE search database validation exceeded its deadline") from exc
            raise CVESearchDatabaseError("CVE search database validation failed") from exc
        except sqlite3.DatabaseError as exc:
            raise CVESearchDatabaseError("CVE search database is corrupt or unreadable") from exc
        finally:
            connection.close()

    @property
    def active_revision(self) -> str:
        """Return the manifest-pinned shard-set revision for this immutable database."""

        return self._expected_revision

    @property
    def record_count(self) -> int:
        """Return the validated number of searchable CVE records."""

        return self._expected_record_count

    @property
    def manifest_sha256(self) -> str:
        """Return the validated source-manifest digest."""

        return self._expected_manifest_sha256

    @property
    def database_sha256(self) -> str:
        """Return the independently validated immutable SQLite artifact digest."""

        return self._expected_database_sha256

    @staticmethod
    def _query_terms(query_text: str) -> tuple[str, ...]:
        normalized = tuple(dict.fromkeys(token.casefold() for token in TOKEN_RE.findall(query_text)))
        if not normalized:
            raise CVESearchQueryError("query must contain at least one alphanumeric term")
        if len(normalized) > MAX_QUERY_TERMS:
            raise CVESearchQueryError(f"query must contain at most {MAX_QUERY_TERMS} unique terms")
        if any(len(term) > MAX_QUERY_TERM_LENGTH for term in normalized):
            raise CVESearchQueryError(f"query terms must be at most {MAX_QUERY_TERM_LENGTH} characters")
        return normalized

    @staticmethod
    def _filter_clauses(
        severity: str,
        published_year: int | None,
        kev: bool | None,
        *,
        alias: str,
    ) -> tuple[list[str], list[object]]:
        clauses: list[str] = []
        parameters: list[object] = []
        if severity:
            clauses.append(f"{alias}.severity = ?")
            parameters.append(severity)
        if published_year is not None:
            clauses.append(f"{alias}.publication_year = ?")
            parameters.append(published_year)
        if kev is not None:
            clauses.append(f"{alias}.kev = ?")
            parameters.append(int(kev))
        return clauses, parameters

    @staticmethod
    def _where_sql(clauses: list[str]) -> str:
        return " WHERE " + " AND ".join(clauses) if clauses else ""

    @staticmethod
    def _preview(row: sqlite3.Row) -> dict[str, Any]:
        cve = str(row["cve"])
        title = str(row["title"])
        severity = str(row["severity"])
        score = row["score"]
        published = str(row["published"])
        ecosystem = str(row["ecosystem"])
        shard = str(row["shard_path"])
        archetypes = [value for value in str(row["archetypes"]).splitlines() if value]
        cve_match = CVE_CANONICAL_RE.fullmatch(cve)
        expected_shard = ""
        if cve_match is not None:
            year, sequence = cve_match.groups()
            expected_shard = f"shards/{year}/{int(sequence) // 1000:04d}.jsonl.gz"
        try:
            valid_publication_date = date.fromisoformat(published).isoformat() == published
        except ValueError:
            valid_publication_date = False
        if (
            cve_match is None
            or not 0 < len(title) <= 500
            or severity not in {"medium", "high", "critical"}
            or type(score) not in {int, float}
            or not 4.0 <= float(score) <= 10.0
            or not valid_publication_date
            or not 0 < len(ecosystem) <= 300
            or type(row["kev"]) is not int
            or row["kev"] not in {0, 1}
            or type(row["has_markdown"]) is not int
            or row["has_markdown"] not in {0, 1}
            or not archetypes
            or len(archetypes) > 64
            or any(len(value) > 160 for value in archetypes)
            or SHARD_PATH_RE.fullmatch(shard) is None
            or shard != expected_shard
        ):
            raise CVESearchDatabaseError("CVE search database returned an invalid preview record")
        return {
            "cve": cve,
            "title": title,
            "severity": severity,
            "score": float(score),
            "published": published,
            "ecosystem": ecosystem,
            "kev": bool(row["kev"]),
            "archetype": archetypes[0],
            "archetypes": archetypes,
            "has_markdown": bool(row["has_markdown"]),
            "shard": shard,
        }

    def _deadline(self, *, timeout_seconds: float | None, deadline: float | None) -> float:
        if timeout_seconds is not None and deadline is not None:
            raise CVESearchQueryError("supply either timeout_seconds or deadline, not both")
        now = self._clock()
        if deadline is not None:
            if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
                raise CVESearchQueryError("deadline must be a finite monotonic timestamp")
            deadline_value = float(deadline)
            if not math.isfinite(deadline_value):
                raise CVESearchQueryError("deadline must be a finite monotonic timestamp")
            return min(deadline_value, now + MAX_QUERY_TIMEOUT_SECONDS)
        if timeout_seconds is None:
            timeout = self._query_timeout_seconds
        else:
            if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
                raise CVESearchQueryError("timeout_seconds must be a finite number")
            timeout = float(timeout_seconds)
            if not math.isfinite(timeout) or not 0 < timeout <= MAX_QUERY_TIMEOUT_SECONDS:
                raise CVESearchQueryError("timeout_seconds is outside the supported range")
        return now + timeout

    def search(
        self,
        query: str = "",
        *,
        severity: str | None = None,
        published_year: int | None = None,
        kev: bool | None = None,
        limit: int = 20,
        timeout_seconds: float | None = None,
        deadline: float | None = None,
    ) -> CVESearchPage:
        """Return a bounded page, exact filtered count, and truncation flag.

        Blank text performs a newest-first browse. Canonical CVE IDs and partial
        canonical prefixes avoid FTS. All other queries become an AND of quoted,
        bounded alphanumeric FTS terms, so FTS operators never reach SQLite.
        """

        if not isinstance(query, str):
            raise CVESearchQueryError("query must be a string")
        query_text = query.strip()
        if len(query_text) > MAX_QUERY_LENGTH:
            raise CVESearchQueryError(f"query must be at most {MAX_QUERY_LENGTH} characters")
        if severity is None:
            severity_key = ""
        elif isinstance(severity, str):
            severity_key = severity.strip().casefold()
        else:
            raise CVESearchQueryError("severity must be 'medium', 'high', 'critical', or null")
        if severity_key not in {"", "medium", "high", "critical"}:
            raise CVESearchQueryError("severity must be 'medium', 'high', 'critical', or null")
        if published_year is not None and (
            type(published_year) is not int or not 1999 <= published_year <= 9999
        ):
            raise CVESearchQueryError("published_year must be an integer between 1999 and 9999")
        if kev is not None and type(kev) is not bool:
            raise CVESearchQueryError("kev must be true, false, or null")
        if type(limit) is not int or not 1 <= limit <= MAX_RESULTS:
            raise CVESearchQueryError(f"limit must be an integer between 1 and {MAX_RESULTS}")

        deadline_value = self._deadline(timeout_seconds=timeout_seconds, deadline=deadline)
        if self._clock() >= deadline_value:
            raise CVESearchTimeoutError("CVE search deadline elapsed before execution")

        exact_cve = query_text.upper()
        filters, filter_parameters = self._filter_clauses(
            severity_key,
            published_year,
            kev,
            alias="c",
        )
        if not query_text:
            count_sql = "SELECT count(*) FROM cves AS c" + self._where_sql(filters)
            result_sql = (
                "SELECT cve, title, severity, score, published, ecosystem, kev, archetypes, "
                "has_markdown, shard_path FROM cves AS c"
                + self._where_sql(filters)
                + " ORDER BY published DESC, cve DESC LIMIT ?"
            )
            count_parameters = list(filter_parameters)
            result_parameters = [*filter_parameters, limit]
        elif CVE_RE.fullmatch(exact_cve):
            exact_filters = ["c.cve = ?", *filters]
            count_sql = "SELECT count(*) FROM cves AS c" + self._where_sql(exact_filters)
            result_sql = (
                "SELECT cve, title, severity, score, published, ecosystem, kev, archetypes, "
                "has_markdown, shard_path FROM cves AS c"
                + self._where_sql(exact_filters)
                + " LIMIT ?"
            )
            count_parameters = [exact_cve, *filter_parameters]
            result_parameters = [exact_cve, *filter_parameters, limit]
        elif CVE_PREFIX_RE.fullmatch(exact_cve):
            prefix_filters = ["c.cve >= ?", "c.cve < ?", *filters]
            count_sql = "SELECT count(*) FROM cves AS c" + self._where_sql(prefix_filters)
            result_sql = (
                "SELECT cve, title, severity, score, published, ecosystem, kev, archetypes, "
                "has_markdown, shard_path FROM cves AS c"
                + self._where_sql(prefix_filters)
                + " ORDER BY severity_rank DESC, kev DESC, score DESC, cve ASC LIMIT ?"
            )
            count_parameters = [exact_cve, exact_cve + "\uffff", *filter_parameters]
            result_parameters = [exact_cve, exact_cve + "\uffff", *filter_parameters, limit]
        else:
            terms = self._query_terms(query_text)
            fts_expression = " AND ".join(f'"{term}"' for term in terms)
            fts_filters = ["cve_fts MATCH ?", *filters]
            from_sql = " FROM cve_fts JOIN cves AS c ON c.id = cve_fts.rowid"
            count_sql = "SELECT count(*)" + from_sql + self._where_sql(fts_filters)
            result_sql = (
                "SELECT c.cve, c.title, c.severity, c.score, c.published, c.ecosystem, c.kev, "
                "c.archetypes, c.has_markdown, c.shard_path"
                + from_sql
                + self._where_sql(fts_filters)
                + " ORDER BY bm25(cve_fts, 12.0, 5.0, 1.0, 1.5, 2.5, 3.0), "
                "c.kev DESC, c.severity_rank DESC, c.score DESC, c.published DESC, c.cve ASC LIMIT ?"
            )
            count_parameters = [fts_expression, *filter_parameters]
            result_parameters = [fts_expression, *filter_parameters, limit]

        connection = self._connect(deadline_value)
        try:
            total_matches = int(connection.execute(count_sql, count_parameters).fetchone()[0])
            rows = connection.execute(result_sql, result_parameters).fetchall()
            results = [self._preview(row) for row in rows]
            self._assert_file_unchanged()
            return {
                "results": results,
                "total_matches": total_matches,
                "truncated": total_matches > len(results),
            }
        except CVESearchRuntimeError:
            raise
        except sqlite3.OperationalError as exc:
            if "interrupted" in str(exc).casefold() or self._clock() >= deadline_value:
                raise CVESearchTimeoutError("CVE search exceeded its execution deadline") from exc
            raise CVESearchDatabaseError("CVE search query failed closed") from exc
        except sqlite3.DatabaseError as exc:
            raise CVESearchDatabaseError("CVE search database became unreadable") from exc
        finally:
            connection.close()


__all__ = [
    "CVESearchDatabaseError",
    "CVESearchPage",
    "CVESearchQueryError",
    "CVESearchRuntime",
    "CVESearchRuntimeError",
    "CVESearchTimeoutError",
]
