from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from scripts import build_cve_search_db as search_db_builder
from scripts import cve_search_runtime as search_runtime
from tests.test_cve_search_runtime import cve_record, write_catalog


ROOT = Path(__file__).resolve().parents[1]
PROD_DATABASE_BYTES = 406_261_760
PROD_IMAGE_START_SECONDS = 36.0
MAX_HEALTH_WINDOW_SECONDS = 600.0


def docker_duration_seconds(value: str) -> float:
    match = re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?", value)
    if match is None or not value:
        raise ValueError(f"unsupported Docker duration: {value!r}")
    hours, minutes, seconds = match.groups()
    return int(hours or 0) * 3600 + int(minutes or 0) * 60 + float(seconds or 0)


def parse_dockerfile_healthcheck(text: str) -> dict[str, float]:
    line = text.split("HEALTHCHECK", maxsplit=1)[1].splitlines()[0]
    flags = dict(re.findall(r"--([a-z-]+)=(\S+)", line))
    return {
        "interval": docker_duration_seconds(flags["interval"]),
        "timeout": docker_duration_seconds(flags["timeout"]),
        "start_period": docker_duration_seconds(flags["start-period"]),
        "retries": int(flags["retries"]),
    }


def parse_deploy_health_timeout(text: str) -> int:
    match = re.search(r'HEALTH_TIMEOUT="\$\{DEPLOY_HEALTH_TIMEOUT:-([0-9]+)\}"', text)
    if match is None:
        raise AssertionError("deploy.sh is missing DEPLOY_HEALTH_TIMEOUT default")
    return int(match.group(1))


class CVESearchValidationDeadlineTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ.pop(search_runtime.VALIDATION_TIMEOUT_ENV, None)
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

    def copy_database(self, name: str) -> Path:
        target = self.root / name
        shutil.copy2(self.database, target)
        return target

    def runtime_for(self, database: Path, **overrides: object) -> search_runtime.CVESearchRuntime:
        return self.runtime(
            database,
            expected_database_sha256=hashlib.sha256(database.read_bytes()).hexdigest(),
            validation_timeout_seconds=search_runtime.MAX_VALIDATION_TIMEOUT_SECONDS,
            **overrides,
        )

    def test_d1_env_var_unset_uses_size_scaled_default(self) -> None:
        resolved = search_runtime.resolve_validation_timeout_seconds(
            self.database.stat().st_size,
            environ={},
        )
        self.assertEqual(
            resolved,
            search_runtime.computed_validation_timeout_seconds(self.database.stat().st_size),
        )
        self.assertEqual(resolved, search_runtime.MIN_VALIDATION_TIMEOUT_SECONDS)
        runtime = self.runtime()
        self.assertEqual(runtime.record_count, self.build_result["records"])

    def test_d1_env_var_valid_int_and_float_are_used(self) -> None:
        self.assertEqual(
            search_runtime.resolve_validation_timeout_seconds(1, environ={search_runtime.VALIDATION_TIMEOUT_ENV: "90"}),
            90.0,
        )
        self.assertEqual(
            search_runtime.resolve_validation_timeout_seconds(
                1, environ={search_runtime.VALIDATION_TIMEOUT_ENV: "97.5"}
            ),
            97.5,
        )
        runtime = self.runtime(validation_timeout_seconds=90)
        self.assertEqual(runtime.record_count, self.build_result["records"])

    def test_d1_env_var_invalid_values_fail_closed(self) -> None:
        invalid = ("0", "-1", "nan", "inf", "+inf", "-inf", "", "abc", "1e9", "true", "false")
        for raw in invalid:
            with self.subTest(raw=raw):
                with self.assertRaises(search_runtime.CVESearchDatabaseError) as raised:
                    search_runtime.resolve_validation_timeout_seconds(
                        1,
                        environ={search_runtime.VALIDATION_TIMEOUT_ENV: raw},
                    )
                message = str(raised.exception)
                self.assertIn(search_runtime.VALIDATION_TIMEOUT_ENV, message)
                self.assertNotIn("falling back", message.casefold())
            with self.subTest(runtime_env=raw):
                with mock.patch.dict(os.environ, {search_runtime.VALIDATION_TIMEOUT_ENV: raw}, clear=False):
                    with self.assertRaises(search_runtime.CVESearchDatabaseError):
                        self.runtime()

    def test_d2_size_scaling_floor_and_hundred_mib_boundaries(self) -> None:
        mib = search_runtime.MIB
        floor_max = 60 * mib
        self.assertEqual(search_runtime.computed_validation_timeout_seconds(0), 15.0)
        self.assertEqual(search_runtime.computed_validation_timeout_seconds(1), 15.0)
        self.assertEqual(search_runtime.computed_validation_timeout_seconds(floor_max), 15.0)
        self.assertEqual(search_runtime.computed_validation_timeout_seconds(floor_max + 1), 16.0)
        for step in (100, 200, 300, 400):
            just_under = step * mib - 1
            exact = step * mib
            just_over = step * mib + 1
            under = search_runtime.computed_validation_timeout_seconds(just_under)
            at_step = search_runtime.computed_validation_timeout_seconds(exact)
            over = search_runtime.computed_validation_timeout_seconds(just_over)
            with self.subTest(step=step):
                self.assertEqual(at_step, float(math.ceil(0.25 * step)))
                self.assertLessEqual(under, at_step)
                self.assertGreaterEqual(over, at_step)
                self.assertEqual(over, at_step + 1)
        empty = self.root / "empty.sqlite3"
        empty.write_bytes(b"")
        with self.assertRaisesRegex(search_runtime.CVESearchDatabaseError, "empty or exceeds"):
            self.runtime(empty)

    def test_d2_and_d3_cap_clamps_size_scaling_and_rejects_epsilon(self) -> None:
        mib = search_runtime.MIB
        cap_bytes = 960 * mib
        self.assertEqual(search_runtime.computed_validation_timeout_seconds(cap_bytes), 240.0)
        self.assertEqual(search_runtime.computed_validation_timeout_seconds(cap_bytes + 1), 240.0)
        self.assertEqual(search_runtime.computed_validation_timeout_seconds((960 + 1) * mib), 240.0)
        self.assertEqual(
            search_runtime.resolve_validation_timeout_seconds(
                1, environ={search_runtime.VALIDATION_TIMEOUT_ENV: "240"}
            ),
            240.0,
        )
        self.assertEqual(
            search_runtime.CVESearchRuntime._validated_timeout(
                240,
                "validation_timeout_seconds",
                maximum=search_runtime.MAX_VALIDATION_TIMEOUT_SECONDS,
            ),
            240.0,
        )
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            search_runtime.resolve_validation_timeout_seconds(
                1,
                environ={search_runtime.VALIDATION_TIMEOUT_ENV: "240.0001"},
            )
        with self.assertRaises(search_runtime.CVESearchDatabaseError):
            search_runtime.CVESearchRuntime._validated_timeout(
                240.0001,
                "validation_timeout_seconds",
                maximum=search_runtime.MAX_VALIDATION_TIMEOUT_SECONDS,
            )
        d0_total = 41.918
        self.assertGreaterEqual(search_runtime.MAX_VALIDATION_TIMEOUT_SECONDS, d0_total * 1.5)

    def test_d5_sha_mismatch_still_fails_closed_under_long_deadline(self) -> None:
        with self.assertRaisesRegex(search_runtime.CVESearchDatabaseError, "digest does not match"):
            self.runtime(
                expected_database_sha256="e" * 64,
                validation_timeout_seconds=search_runtime.MAX_VALIDATION_TIMEOUT_SECONDS,
            )

    def test_d5_header_and_mid_file_corruption_still_fail_closed(self) -> None:
        header = self.copy_database("header-flip.sqlite3")
        header_bytes = bytearray(header.read_bytes())
        header_bytes[0] ^= 0xFF
        header.write_bytes(header_bytes)
        with self.assertRaises(search_runtime.CVESearchDatabaseError) as header_error:
            self.runtime_for(header)
        self.assertNotIn("deadline", str(header_error.exception).casefold())

        mid = self.copy_database("mid-flip.sqlite3")
        mid_bytes = bytearray(mid.read_bytes())
        mid_bytes[len(mid_bytes) // 2] ^= 0xFF
        mid.write_bytes(mid_bytes)
        with self.assertRaises(search_runtime.CVESearchDatabaseError) as mid_error:
            self.runtime_for(mid)
        self.assertNotIn("deadline", str(mid_error.exception).casefold())

    def test_d5_fts_count_mismatch_still_fails_closed(self) -> None:
        mutated = self.copy_database("fts-count.sqlite3")
        with closing(sqlite3.connect(mutated)) as connection:
            connection.execute("UPDATE metadata SET value = '2' WHERE key = 'record_count'")
            connection.commit()
        with self.assertRaisesRegex(search_runtime.CVESearchDatabaseError, "content count"):
            self.runtime_for(mutated, expected_record_count=2)

    def test_d5_docsize_gap_still_fails_closed(self) -> None:
        mutated = self.copy_database("docsize-gap.sqlite3")
        with closing(sqlite3.connect(mutated)) as connection:
            connection.execute("DELETE FROM cve_fts_docsize WHERE id = (SELECT max(id) FROM cves)")
            connection.commit()
        with self.assertRaisesRegex(search_runtime.CVESearchDatabaseError, "document coverage"):
            self.runtime_for(mutated)

    def test_d5_fts_boundary_row_missing_still_fails_closed(self) -> None:
        mutated = self.copy_database("fts-boundary.sqlite3")
        with closing(sqlite3.connect(mutated)) as connection:
            row = connection.execute(
                "SELECT id, cve, title, summary, ecosystem, archetypes, products "
                "FROM cves WHERE id = (SELECT max(id) FROM cves)"
            ).fetchone()
            saved_docsize = connection.execute(
                "SELECT sz FROM cve_fts_docsize WHERE id = ?",
                (row[0],),
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO cve_fts(cve_fts, rowid, cve, title, summary, ecosystem, archetypes, products) "
                "VALUES('delete', ?, ?, ?, ?, ?, ?, ?)",
                row,
            )
            connection.execute(
                "INSERT INTO cve_fts_docsize(id, sz) VALUES(?, ?)",
                (row[0], saved_docsize),
            )
            connection.commit()
            missing = connection.execute(
                "SELECT 1 FROM cve_fts WHERE cve_fts MATCH ? AND rowid = ?",
                (f'"{row[1]}"', row[0]),
            ).fetchone()
            self.assertIsNone(missing)
        with self.assertRaisesRegex(search_runtime.CVESearchDatabaseError, "FTS index is incomplete"):
            self.runtime_for(mutated)

    def test_d5_quick_check_not_ok_still_fails_closed(self) -> None:
        original_connect = search_runtime.CVESearchRuntime._connect

        class _QuickCheckFail:
            def __init__(self, inner: sqlite3.Connection) -> None:
                self._inner = inner

            def execute(self, sql: str, parameters: object = ()) -> object:
                if "quick_check" in str(sql).casefold():
                    return [("malformed",)]
                return self._inner.execute(sql, parameters)

            def close(self) -> None:
                self._inner.close()

            def __getattr__(self, name: str) -> object:
                return getattr(self._inner, name)

        def connect(runtime: search_runtime.CVESearchRuntime, deadline: float) -> object:
            return _QuickCheckFail(original_connect(runtime, deadline))

        with mock.patch.object(search_runtime.CVESearchRuntime, "_connect", connect):
            with self.assertRaisesRegex(
                search_runtime.CVESearchDatabaseError,
                "structural integrity check",
            ):
                self.runtime(validation_timeout_seconds=search_runtime.MAX_VALIDATION_TIMEOUT_SECONDS)

    def test_d6_deadline_is_enforced_in_digest_phase(self) -> None:
        calls = {"n": 0}

        def fake_clock() -> float:
            calls["n"] += 1
            return 0.0 if calls["n"] <= 2 else 1.0

        with mock.patch("scripts.cve_search_runtime.time.monotonic", fake_clock):
            with self.assertRaisesRegex(
                search_runtime.CVESearchDatabaseError,
                "digest validation exceeded its deadline",
            ):
                self.runtime(validation_timeout_seconds=0.5)
        self.assertGreater(calls["n"], 2)

    def test_d6_deadline_is_enforced_in_sqlite_phase(self) -> None:
        original_digest = search_runtime.CVESearchRuntime._database_sha256
        phase = {"name": "init"}

        def digest(self: search_runtime.CVESearchRuntime, deadline: float) -> str:
            phase["name"] = "digest"
            try:
                return original_digest(self, deadline)
            finally:
                phase["name"] = "sqlite"

        def fake_clock() -> float:
            if phase["name"] != "sqlite":
                return 0.0
            return 1.0

        with mock.patch("scripts.cve_search_runtime.time.monotonic", fake_clock):
            with mock.patch.object(search_runtime.CVESearchRuntime, "_database_sha256", digest):
                with mock.patch.object(search_runtime, "PROGRESS_HANDLER_STEPS", 1):
                    with self.assertRaisesRegex(
                        search_runtime.CVESearchDatabaseError,
                        "validation exceeded its deadline",
                    ):
                        self.runtime(validation_timeout_seconds=0.5)
        self.assertEqual(phase["name"], "sqlite")

    def test_d7_shared_budget_leaves_digest_remainder_for_sqlite(self) -> None:
        original_digest = search_runtime.CVESearchRuntime._database_sha256
        state = {"deadline_started": False, "in_digest": False}

        def digest(self: search_runtime.CVESearchRuntime, deadline: float) -> str:
            state["in_digest"] = True
            try:
                return original_digest(self, deadline)
            finally:
                state["in_digest"] = False

        def fake_clock() -> float:
            if not state["deadline_started"]:
                state["deadline_started"] = True
                return 0.0
            if state["in_digest"]:
                return 9.0
            return 10.1

        with mock.patch("scripts.cve_search_runtime.time.monotonic", fake_clock):
            with mock.patch.object(search_runtime.CVESearchRuntime, "_database_sha256", digest):
                with mock.patch.object(search_runtime, "PROGRESS_HANDLER_STEPS", 1):
                    with self.assertRaisesRegex(
                        search_runtime.CVESearchDatabaseError,
                        "validation exceeded its deadline",
                    ):
                        self.runtime(validation_timeout_seconds=10.0)

    def test_d8_health_windows_cover_cap_and_406mb_deadline(self) -> None:
        dockerfile = (ROOT / "Dockerfile.mcp-server").read_text(encoding="utf-8")
        deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")
        healthcheck = parse_dockerfile_healthcheck(dockerfile)
        health_window = healthcheck["start_period"] + healthcheck["interval"] * healthcheck["retries"]
        deploy_timeout = parse_deploy_health_timeout(deploy)
        deadline = search_runtime.computed_validation_timeout_seconds(PROD_DATABASE_BYTES)
        margin = search_runtime.HEALTHCHECK_DEADLINE_MARGIN_SECONDS
        self.assertEqual(deadline, 97.0)
        self.assertGreaterEqual(health_window, deadline + margin)
        self.assertGreaterEqual(
            health_window,
            search_runtime.MAX_VALIDATION_TIMEOUT_SECONDS + margin,
        )
        self.assertLessEqual(health_window, MAX_HEALTH_WINDOW_SECONDS)
        self.assertGreaterEqual(
            deploy_timeout,
            search_runtime.MAX_VALIDATION_TIMEOUT_SECONDS + margin + PROD_IMAGE_START_SECONDS,
        )
        self.assertLessEqual(deploy_timeout, MAX_HEALTH_WINDOW_SECONDS)

    def test_d10_digest_stays_chunked_and_sqlite_cache_is_unchanged(self) -> None:
        reads: list[int] = []
        real_open = Path.open
        target = self.database.resolve()

        def spy_open(path: Path, *args: object, **kwargs: object):
            stream = real_open(path, *args, **kwargs)
            if path.resolve() == target and kwargs.get("buffering") == 0:
                real_read = stream.read

                def read(size: int = -1) -> bytes:
                    reads.append(size)
                    if size == -1:
                        raise AssertionError("CVE search digest must not read the database in one shot")
                    return real_read(size)

                stream.read = read  # type: ignore[method-assign]
            return stream

        with mock.patch("pathlib.Path.open", spy_open):
            runtime = self.runtime()
        self.assertTrue(reads)
        self.assertTrue(all(size == search_runtime.MIB for size in reads))
        connection = runtime._connect(runtime._clock() + 1.0)
        try:
            self.assertEqual(connection.execute("PRAGMA cache_size").fetchone()[0], -4096)
            self.assertEqual(connection.execute("PRAGMA mmap_size").fetchone()[0], 0)
        finally:
            connection.close()

    def test_d12_scale_harness_omitted_timeout_uses_size_scaled_default(self) -> None:
        runtime = search_runtime.CVESearchRuntime(
            self.database,
            expected_revision=self.build_result["shard_set_sha256"],
            expected_record_count=self.build_result["records"],
            expected_manifest_sha256=self.build_result["manifest_sha256"],
            expected_database_sha256=self.database_sha256,
        )
        self.assertEqual(runtime.record_count, self.build_result["records"])


if __name__ == "__main__":
    unittest.main()
